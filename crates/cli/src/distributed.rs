use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use discovery::{DiscoveryMode, default_top_ports};
use redis::aio::MultiplexedConnection;
use reporter::ScanResult;
use serde::{Deserialize, Serialize};
use temu_core::AppConfig;
use tokio::time::{Instant, sleep};

use crate::orchestrator::{MultiTargetScanResult, aggregate_scan_results, load_target_list};

/// Redis list containing serialized scan tasks.
pub const TASK_QUEUE: &str = "temu:tasks";
/// Redis list containing serialized scan results.
pub const RESULT_QUEUE: &str = "temu:results";
/// Redis key prefix for task status values.
pub const STATUS_PREFIX: &str = "temu:status:";
/// Redis key prefix for worker heartbeats.
pub const WORKER_PREFIX: &str = "temu:workers:";

const DEFAULT_COLLECT_TIMEOUT_SECS: u64 = 3600;
const WORKER_HEARTBEAT_TTL_SECS: usize = 30;

/// A distributed scan task stored as JSON in Redis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributedScanTask {
    pub id: String,
    pub batch_id: String,
    pub target: String,
    pub created_at: DateTime<Utc>,
}

/// A distributed scan result stored as JSON in Redis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedScanResult {
    pub task_id: String,
    pub batch_id: String,
    pub target: String,
    pub worker_id: String,
    pub status: DistributedTaskStatus,
    pub result: Option<ScanResult>,
    pub error: Option<String>,
    pub finished_at: DateTime<Utc>,
}

/// Status value for a distributed scan task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistributedTaskStatus {
    Queued,
    Running,
    Done,
    Failed,
}

/// Lightweight dashboard counters for the distributed queues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributedDashboard {
    pub workers: usize,
    pub pending_tasks: usize,
    pub completed_results: usize,
}

/// Runs one distributed worker loop.
///
/// The worker polls `temu:tasks`, executes scans, and pushes serialized results
/// to `temu:results`. When `run_once` is true the worker exits after one task
/// or after a short idle timeout.
pub async fn run_worker(redis_url: &str, config: &AppConfig, run_once: bool) -> anyhow::Result<()> {
    run_worker_with_ports(redis_url, config, run_once, &default_top_ports()).await
}

/// Runs one distributed worker loop with explicit TCP ports.
pub async fn run_worker_with_ports(
    redis_url: &str,
    config: &AppConfig,
    run_once: bool,
    ports: &[u16],
) -> anyhow::Result<()> {
    let mut connection = redis_connection(redis_url).await?;
    let worker_id = worker_id();

    eprintln!("[*] Worker {worker_id} polling {TASK_QUEUE}");
    loop {
        heartbeat_worker(&mut connection, &worker_id).await?;
        let Some(task) = pop_task(&mut connection, 5).await? else {
            if run_once {
                return Ok(());
            }
            continue;
        };

        set_task_status(&mut connection, &task.id, DistributedTaskStatus::Running).await?;
        let result = crate::orchestrator::run_scan_with_ports(
            &task.target,
            config,
            DiscoveryMode::Hybrid,
            ports,
        )
        .await;

        let distributed_result = match result {
            Ok(scan_result) => {
                set_task_status(&mut connection, &task.id, DistributedTaskStatus::Done).await?;
                DistributedScanResult {
                    task_id: task.id,
                    batch_id: task.batch_id,
                    target: task.target,
                    worker_id: worker_id.clone(),
                    status: DistributedTaskStatus::Done,
                    result: Some(scan_result),
                    error: None,
                    finished_at: Utc::now(),
                }
            }
            Err(error) => {
                set_task_status(&mut connection, &task.id, DistributedTaskStatus::Failed).await?;
                DistributedScanResult {
                    task_id: task.id,
                    batch_id: task.batch_id,
                    target: task.target,
                    worker_id: worker_id.clone(),
                    status: DistributedTaskStatus::Failed,
                    result: None,
                    error: Some(error.to_string()),
                    finished_at: Utc::now(),
                }
            }
        };
        push_result(&mut connection, &distributed_result).await?;

        if run_once {
            return Ok(());
        }
    }
}

/// Runs the distributed coordinator.
///
/// Targets are loaded from `list_path`, pushed into Redis, collected from
/// workers, and aggregated into one `ScanResult`.
pub async fn run_coordinator(
    redis_url: &str,
    list_path: &Path,
    collect_timeout: Duration,
) -> anyhow::Result<MultiTargetScanResult> {
    let targets = load_target_list(list_path)?;
    let batch_id = batch_id();
    let mut connection = redis_connection(redis_url).await?;

    enqueue_targets(&mut connection, &batch_id, &targets).await?;
    eprintln!(
        "[*] Coordinator queued {} targets in batch {batch_id}",
        targets.len()
    );

    let mut successful = Vec::new();
    let mut failures = HashMap::new();
    let deadline = Instant::now() + collect_timeout;

    while successful.len() + failures.len() < targets.len() {
        let dashboard = load_dashboard(&mut connection).await?;
        eprintln!(
            "[*] Dashboard: workers={} pending={} done={}/{}",
            dashboard.workers,
            dashboard.pending_tasks,
            successful.len() + failures.len(),
            targets.len()
        );

        if Instant::now() >= deadline {
            break;
        }

        let Some(result) = pop_result(&mut connection, 5).await? else {
            continue;
        };
        if result.batch_id != batch_id {
            push_result(&mut connection, &result).await?;
            sleep(Duration::from_millis(250)).await;
            continue;
        }

        match (result.status, result.result) {
            (DistributedTaskStatus::Done, Some(scan_result)) => successful.push(scan_result),
            _ => {
                failures.insert(
                    result.task_id,
                    result
                        .error
                        .unwrap_or_else(|| "worker returned no scan result".to_string()),
                );
            }
        }
    }

    if successful.is_empty() {
        return Err(anyhow::anyhow!(
            "No distributed tasks completed successfully; failures={}",
            failures.len()
        ));
    }

    let aggregate_target = format!("distributed:{}:{}", list_path.display(), batch_id);
    let aggregate = aggregate_scan_results(&aggregate_target, &successful);
    Ok(MultiTargetScanResult {
        aggregate,
        targets: successful,
    })
}

/// Runs the coordinator with the default collection timeout.
pub async fn run_coordinator_default(
    redis_url: &str,
    list_path: &Path,
) -> anyhow::Result<MultiTargetScanResult> {
    run_coordinator(
        redis_url,
        list_path,
        Duration::from_secs(DEFAULT_COLLECT_TIMEOUT_SECS),
    )
    .await
}

/// Loads the current distributed queue dashboard counters.
pub async fn load_dashboard(
    connection: &mut MultiplexedConnection,
) -> anyhow::Result<DistributedDashboard> {
    let pending_tasks: usize = redis::cmd("LLEN")
        .arg(TASK_QUEUE)
        .query_async(connection)
        .await?;
    let completed_results: usize = redis::cmd("LLEN")
        .arg(RESULT_QUEUE)
        .query_async(connection)
        .await?;
    let workers: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{WORKER_PREFIX}*"))
        .query_async(connection)
        .await?;

    Ok(DistributedDashboard {
        workers: workers.len(),
        pending_tasks,
        completed_results,
    })
}

/// Builds the Redis status key for a task id.
pub fn status_key(task_id: &str) -> String {
    format!("{STATUS_PREFIX}{task_id}")
}

async fn redis_connection(redis_url: &str) -> anyhow::Result<MultiplexedConnection> {
    let client = redis::Client::open(redis_url)?;
    Ok(client.get_multiplexed_async_connection().await?)
}

async fn enqueue_targets(
    connection: &mut MultiplexedConnection,
    batch_id: &str,
    targets: &[String],
) -> anyhow::Result<Vec<DistributedScanTask>> {
    let mut tasks = Vec::with_capacity(targets.len());
    for (index, target) in targets.iter().enumerate() {
        let task = DistributedScanTask {
            id: format!("{batch_id}-{index:06}"),
            batch_id: batch_id.to_string(),
            target: target.clone(),
            created_at: Utc::now(),
        };
        let payload = serde_json::to_string(&task)?;
        let _: usize = redis::cmd("RPUSH")
            .arg(TASK_QUEUE)
            .arg(payload)
            .query_async(&mut *connection)
            .await?;
        set_task_status(connection, &task.id, DistributedTaskStatus::Queued).await?;
        tasks.push(task);
    }
    Ok(tasks)
}

async fn pop_task(
    connection: &mut MultiplexedConnection,
    timeout_secs: usize,
) -> anyhow::Result<Option<DistributedScanTask>> {
    let value: Option<(String, String)> = redis::cmd("BLPOP")
        .arg(TASK_QUEUE)
        .arg(timeout_secs)
        .query_async(connection)
        .await?;
    value
        .map(|(_, payload)| serde_json::from_str(&payload).map_err(anyhow::Error::from))
        .transpose()
}

async fn pop_result(
    connection: &mut MultiplexedConnection,
    timeout_secs: usize,
) -> anyhow::Result<Option<DistributedScanResult>> {
    let value: Option<(String, String)> = redis::cmd("BLPOP")
        .arg(RESULT_QUEUE)
        .arg(timeout_secs)
        .query_async(connection)
        .await?;
    value
        .map(|(_, payload)| serde_json::from_str(&payload).map_err(anyhow::Error::from))
        .transpose()
}

async fn push_result(
    connection: &mut MultiplexedConnection,
    result: &DistributedScanResult,
) -> anyhow::Result<()> {
    let payload = serde_json::to_string(result)?;
    let _: usize = redis::cmd("RPUSH")
        .arg(RESULT_QUEUE)
        .arg(payload)
        .query_async(connection)
        .await?;
    Ok(())
}

async fn set_task_status(
    connection: &mut MultiplexedConnection,
    task_id: &str,
    status: DistributedTaskStatus,
) -> anyhow::Result<()> {
    let payload = serde_json::to_string(&status)?;
    let _: () = redis::cmd("SET")
        .arg(status_key(task_id))
        .arg(payload)
        .query_async(connection)
        .await?;
    Ok(())
}

async fn heartbeat_worker(
    connection: &mut MultiplexedConnection,
    worker_id: &str,
) -> anyhow::Result<()> {
    let _: () = redis::cmd("SETEX")
        .arg(format!("{WORKER_PREFIX}{worker_id}"))
        .arg(WORKER_HEARTBEAT_TTL_SECS)
        .arg(Utc::now().to_rfc3339())
        .query_async(connection)
        .await?;
    Ok(())
}

fn worker_id() -> String {
    format!("{}-{}", std::process::id(), Utc::now().timestamp_millis())
}

fn batch_id() -> String {
    format!("batch-{}", Utc::now().timestamp_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_key_uses_expected_prefix() {
        assert_eq!(status_key("task-1"), "temu:status:task-1");
    }

    #[test]
    fn test_scan_task_json_roundtrip() {
        let task = DistributedScanTask {
            id: "task-1".to_string(),
            batch_id: "batch-1".to_string(),
            target: "https://example.com".to_string(),
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&task).unwrap();
        let decoded: DistributedScanTask = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, task);
    }

    #[test]
    fn test_task_status_serializes_as_snake_case() {
        let json = serde_json::to_string(&DistributedTaskStatus::Running).unwrap();
        assert_eq!(json, "\"running\"");
    }
}

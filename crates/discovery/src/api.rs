use std::collections::{HashMap, HashSet};
use std::time::Duration;

use reqwest::{Client, Method, Url};
use serde_json::{Value, json};
use temu_core::{AppConfig, Asset, AssetType, TemuError};
use tracing::{debug, info, warn};

const SPEC_PATHS: &[&str] = &[
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/api-docs",
    "/api-docs.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/swagger/v1/swagger.json",
    "/docs/openapi.json",
];
const GRAPHQL_PATHS: &[&str] = &["/graphql", "/api/graphql", "/graphiql"];
const HTTP_METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "trace",
];
const MAX_SPEC_BYTES: usize = 4 * 1024 * 1024;
const MAX_GRAPHQL_BYTES: usize = 512 * 1024;

/// Discovers API surfaces by probing OpenAPI/Swagger specs and common GraphQL
/// endpoints.
///
/// Generated assets are same-origin `AssetType::ApiEndpoint` values so they can
/// flow into reporting and vulnerability scanning without changing downstream
/// contracts.
pub async fn run_api_discovery(
    base_url: &str,
    config: &AppConfig,
) -> Result<Vec<Asset>, TemuError> {
    let base = Url::parse(base_url).map_err(|e| {
        TemuError::Parse(format!("Invalid API discovery base URL '{base_url}': {e}"))
    })?;
    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(&config.user_agent)
        .build()
        .map_err(TemuError::from_network)?;

    let mut assets = Vec::new();
    let mut seen = HashSet::new();

    for spec_path in SPEC_PATHS {
        let Some(spec_url) = base.join(spec_path.trim_start_matches('/')).ok() else {
            continue;
        };
        let Some(body) = fetch_text(&client, spec_url.clone(), MAX_SPEC_BYTES).await else {
            continue;
        };
        let Some(spec) = parse_spec_document(&body) else {
            continue;
        };

        record_asset(
            &mut assets,
            &mut seen,
            spec_url.as_str(),
            "discovery::openapi_spec",
        );
        for endpoint in endpoints_from_openapi(&base, &spec) {
            record_asset(
                &mut assets,
                &mut seen,
                endpoint.as_str(),
                "discovery::openapi",
            );
        }
    }

    for graphql_path in GRAPHQL_PATHS {
        let Some(graphql_url) = base.join(graphql_path.trim_start_matches('/')).ok() else {
            continue;
        };
        if let Some(asset_source) = detect_graphql(&client, graphql_url.clone()).await {
            record_asset(&mut assets, &mut seen, graphql_url.as_str(), &asset_source);
        }
    }

    info!("API discovery complete: {} assets", assets.len());
    Ok(assets)
}

async fn fetch_text(client: &Client, url: Url, max_bytes: usize) -> Option<String> {
    debug!("API discovery fetch {url}");
    let response = match client.get(url.clone()).send().await {
        Ok(response) => response,
        Err(e) => {
            warn!("API discovery request failed for {url}: {e}");
            return None;
        }
    };
    if !response.status().is_success() {
        return None;
    }

    let bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!("API discovery body read failed for {url}: {e}");
            return None;
        }
    };
    let limited = &bytes[..bytes.len().min(max_bytes)];
    Some(String::from_utf8_lossy(limited).into_owned())
}

fn parse_spec_document(body: &str) -> Option<Value> {
    serde_json::from_str::<Value>(body)
        .ok()
        .or_else(|| serde_yaml::from_str::<Value>(body).ok())
        .filter(is_openapi_document)
}

fn is_openapi_document(value: &Value) -> bool {
    value.get("openapi").and_then(Value::as_str).is_some()
        || value.get("swagger").and_then(Value::as_str).is_some()
}

fn endpoints_from_openapi(base: &Url, spec: &Value) -> Vec<Url> {
    let Some(paths) = spec.get("paths").and_then(Value::as_object) else {
        return Vec::new();
    };

    let mut endpoints = Vec::new();
    for (path_template, item) in paths {
        let Some(path_item) = item.as_object() else {
            continue;
        };
        let inherited_parameters = path_item
            .get("parameters")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        for method in HTTP_METHODS {
            let Some(operation) = path_item.get(*method).and_then(Value::as_object) else {
                continue;
            };
            let mut parameters = inherited_parameters.clone();
            if let Some(operation_parameters) =
                operation.get("parameters").and_then(Value::as_array)
            {
                parameters.extend(operation_parameters.iter().cloned());
            }

            if let Some(url) = endpoint_url_from_operation(base, path_template, &parameters) {
                endpoints.push(url);
            }
        }
    }

    endpoints
}

fn endpoint_url_from_operation(
    base: &Url,
    path_template: &str,
    parameters: &[Value],
) -> Option<Url> {
    let mut path = path_template.to_string();
    let mut query_values = HashMap::new();

    for parameter in parameters {
        let Some(parameter) = parameter.as_object() else {
            continue;
        };
        let Some(name) = parameter.get("name").and_then(Value::as_str) else {
            continue;
        };
        let location = parameter
            .get("in")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match location {
            "path" => {
                let placeholder = format!("{{{name}}}");
                path = path.replace(&placeholder, "1");
            }
            "query" => {
                query_values.insert(name.to_string(), benign_value_for_parameter(parameter));
            }
            _ => {}
        }
    }

    let mut url = base.join(path.trim_start_matches('/')).ok()?;
    if !query_values.is_empty() {
        let mut pairs = url.query_pairs_mut();
        let mut ordered: Vec<_> = query_values.into_iter().collect();
        ordered.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, value) in ordered {
            pairs.append_pair(&name, &value);
        }
    }
    Some(url)
}

fn benign_value_for_parameter(parameter: &serde_json::Map<String, Value>) -> String {
    let schema = parameter.get("schema").and_then(Value::as_object);
    match schema
        .and_then(|schema| schema.get("type"))
        .and_then(Value::as_str)
    {
        Some("integer") | Some("number") => "1".to_string(),
        Some("boolean") => "false".to_string(),
        _ => "temu".to_string(),
    }
}

async fn detect_graphql(client: &Client, graphql_url: Url) -> Option<String> {
    let body = fetch_text(client, graphql_url.clone(), MAX_GRAPHQL_BYTES).await;
    if let Some(body) = &body
        && (body.contains("GraphiQL")
            || body.contains("graphql")
            || body.contains("__schema")
            || body.contains("Cannot query field"))
    {
        return Some("discovery::graphql".to_string());
    }

    let introspection = json!({
        "query": "query TemuIntrospectionProbe { __schema { queryType { name } } }"
    });
    let response = client
        .request(Method::POST, graphql_url.clone())
        .json(&introspection)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let bytes = response.bytes().await.ok()?;
    let limited = &bytes[..bytes.len().min(MAX_GRAPHQL_BYTES)];
    let body = String::from_utf8_lossy(limited);

    if body.contains("__schema") && body.contains("queryType") {
        Some("discovery::graphql_introspection_exposed:medium".to_string())
    } else if body.contains("errors") && body.contains("GraphQL") {
        Some("discovery::graphql_verbose_errors:low".to_string())
    } else {
        Some("discovery::graphql".to_string())
    }
}

fn record_asset(
    assets: &mut Vec<Asset>,
    seen: &mut HashSet<String>,
    url: &str,
    discovered_by: &str,
) {
    if seen.insert(format!("{discovered_by}:{url}")) {
        assets.push(Asset::new(
            url.to_string(),
            AssetType::ApiEndpoint,
            discovered_by,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config() -> AppConfig {
        AppConfig {
            rate_limit: 10,
            timeout_secs: 5,
            concurrency: 4,
            user_agent: "Temu-Test/1.0".to_string(),
            output_dir: PathBuf::from("/tmp"),
            rules_dir: PathBuf::from("/tmp"),
            dictionaries_dir: PathBuf::from("/tmp"),
            max_recursion_depth: 2,
            wordlist_override: None,
            allow_risky_rules: false,
            browser_crawl_enabled: true,
            browser_crawl_max_pages: 25,
            browser_crawl_max_depth: 2,
            browser_crawl_render_js: false,
            browser_crawl_browser_path: None,
        }
    }

    #[test]
    fn test_endpoints_from_openapi_generates_safe_parameters() {
        let base = Url::parse("https://example.com").unwrap();
        let spec = json!({
            "openapi": "3.0.0",
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [
                            {"name": "id", "in": "path", "schema": {"type": "integer"}},
                            {"name": "active", "in": "query", "schema": {"type": "boolean"}}
                        ]
                    }
                }
            }
        });

        let endpoints = endpoints_from_openapi(&base, &spec);

        assert_eq!(endpoints.len(), 1);
        assert_eq!(
            endpoints[0].as_str(),
            "https://example.com/users/1?active=false"
        );
    }

    #[tokio::test]
    async fn test_api_discovery_parses_openapi_and_graphql() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/openapi.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "openapi": "3.0.0",
                "paths": {
                    "/api/products": {"get": {}},
                    "/api/users/{id}": {
                        "get": {
                            "parameters": [
                                {"name": "id", "in": "path", "schema": {"type": "integer"}},
                                {"name": "q", "in": "query", "schema": {"type": "string"}}
                            ]
                        }
                    }
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(body_string_contains("__schema"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {"__schema": {"queryType": {"name": "Query"}}}
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let assets = run_api_discovery(&server.uri(), &test_config())
            .await
            .expect("api discovery should succeed");
        let urls: HashSet<_> = assets.iter().map(|asset| asset.url.as_str()).collect();
        let sources: HashSet<_> = assets
            .iter()
            .map(|asset| asset.discovered_by.as_str())
            .collect();

        let products_url = format!("{}/api/products", server.uri());
        let users_url = format!("{}/api/users/1?q=temu", server.uri());
        let graphql_url = format!("{}/graphql", server.uri());

        assert!(urls.contains(products_url.as_str()));
        assert!(urls.contains(users_url.as_str()));
        assert!(urls.contains(graphql_url.as_str()));
        assert!(sources.contains("discovery::graphql_introspection_exposed:medium"));
    }
}

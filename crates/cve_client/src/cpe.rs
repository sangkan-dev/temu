use std::collections::HashMap;
use std::sync::LazyLock;

use fingerprint::TechStack;
use serde::{Deserialize, Serialize};

/// Why a fingerprinted technology could or could not be queried through CPE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicabilityStatus {
    Applicable,
    MissingVersion,
    UnknownProductMapping,
}

/// Explainable mapping between a detected technology and its NVD CPE query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpeApplicability {
    pub technology: String,
    pub detected_version: Option<String>,
    pub confidence: f32,
    pub status: ApplicabilityStatus,
    pub cpe: Option<String>,
    pub reason: String,
}

static CPE_MAP: LazyLock<HashMap<&'static str, (&'static str, &'static str)>> =
    LazyLock::new(|| {
        HashMap::from([
            ("nginx", ("f5", "nginx")),
            ("apache", ("apache", "http_server")),
            ("apache httpd", ("apache", "http_server")),
            ("apache http server", ("apache", "http_server")),
            ("php", ("php", "php")),
            ("wordpress", ("wordpress", "wordpress")),
            ("drupal", ("drupal", "drupal")),
            ("joomla", ("joomla", "joomla\\!")),
            ("magento", ("magento", "magento")),
            ("jquery", ("jquery", "jquery")),
            ("bootstrap", ("getbootstrap", "bootstrap")),
            ("react", ("facebook", "react")),
            ("vue.js", ("vuejs", "vue.js")),
            ("angular", ("angular", "angular")),
            ("node.js", ("nodejs", "node.js")),
            ("nodejs", ("nodejs", "node.js")),
            ("express", ("expressjs", "express")),
            ("django", ("djangoproject", "django")),
            ("ruby on rails", ("rubyonrails", "rails")),
            ("spring", ("vmware", "spring_framework")),
            ("spring framework", ("vmware", "spring_framework")),
            ("tomcat", ("apache", "tomcat")),
            ("openssl", ("openssl", "openssl")),
            ("mysql", ("oracle", "mysql")),
            ("mariadb", ("mariadb", "mariadb")),
            ("postgresql", ("postgresql", "postgresql")),
            ("postgres", ("postgresql", "postgresql")),
            ("redis", ("redis", "redis")),
            ("elasticsearch", ("elastic", "elasticsearch")),
            ("kibana", ("elastic", "kibana")),
            ("grafana", ("grafana", "grafana")),
            ("jenkins", ("jenkins", "jenkins")),
            ("gitlab", ("gitlab", "gitlab")),
            ("next.js", ("vercel", "next.js")),
            ("nuxt.js", ("nuxt", "nuxt.js")),
            ("laravel", ("laravel", "laravel")),
            ("iis", ("microsoft", "internet_information_services")),
            ("asp.net", ("microsoft", "asp.net")),
            ("caddy", ("caddyserver", "caddy")),
            ("litespeed", ("litespeedtech", "litespeed_web_server")),
            ("openresty", ("openresty", "openresty")),
            ("haproxy", ("haproxy", "haproxy")),
            ("varnish", ("varnish-cache", "varnish_cache")),
            ("envoy", ("envoyproxy", "envoy")),
            ("traefik", ("traefik", "traefik")),
            ("cloudflare", ("cloudflare", "cloudflare")),
            ("sucuri", ("sucuri", "sucuri")),
            ("ghost", ("ghost", "ghost")),
            ("typo3", ("typo3", "typo3")),
            ("shopify", ("shopify", "shopify")),
            ("lodash", ("lodash", "lodash")),
            ("moment.js", ("momentjs", "moment")),
            ("axios", ("axios", "axios")),
            ("webpack", ("webpack", "webpack")),
            ("gunicorn", ("gunicorn", "gunicorn")),
            ("python", ("python", "python")),
        ])
    });

/// Builds a CPE 2.3 name from a detected technology and version.
pub fn build_cpe(tech: &TechStack) -> Option<String> {
    explain_cpe_applicability(tech).cpe
}

/// Maps a fingerprint to CPE and provides an audit-friendly applicability reason.
pub fn explain_cpe_applicability(tech: &TechStack) -> CpeApplicability {
    let version = tech
        .version
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let Some(version) = version else {
        return CpeApplicability {
            technology: tech.name.clone(),
            detected_version: tech.version.clone(),
            confidence: tech.confidence,
            status: ApplicabilityStatus::MissingVersion,
            cpe: None,
            reason: format!(
                "{} was detected, but no version was observed; NVD CPE applicability cannot be established",
                tech.name
            ),
        };
    };

    let key = tech.name.to_ascii_lowercase();
    let Some((vendor, product)) = CPE_MAP.get(key.as_str()) else {
        return CpeApplicability {
            technology: tech.name.clone(),
            detected_version: Some(version.to_string()),
            confidence: tech.confidence,
            status: ApplicabilityStatus::UnknownProductMapping,
            cpe: None,
            reason: format!(
                "{} {} was detected, but no CPE alias is configured for this product",
                tech.name, version
            ),
        };
    };

    let cpe = format!(
        "cpe:2.3:a:{vendor}:{product}:{}:*:*:*:*:*:*:*",
        sanitize_version(version)
    );
    CpeApplicability {
        technology: tech.name.clone(),
        detected_version: Some(version.to_string()),
        confidence: tech.confidence,
        status: ApplicabilityStatus::Applicable,
        cpe: Some(cpe.clone()),
        reason: format!(
            "{} {} fingerprint (confidence {:.2}) maps to CPE {cpe}",
            tech.name, version, tech.confidence
        ),
    }
}

fn sanitize_version(version: &str) -> String {
    version.trim().replace(' ', "_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use fingerprint::TechCategory;

    fn tech(name: &str, version: Option<&str>) -> TechStack {
        TechStack::new(
            name,
            version.map(str::to_string),
            0.95,
            TechCategory::WebServer,
        )
    }

    #[test]
    fn test_build_cpe_common_technologies() {
        assert_eq!(
            build_cpe(&tech("nginx", Some("1.18.0"))).unwrap(),
            "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"
        );
        assert_eq!(
            build_cpe(&tech("Apache", Some("2.4.51"))).unwrap(),
            "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"
        );
        assert_eq!(
            build_cpe(&tech("PHP", Some("8.1"))).unwrap(),
            "cpe:2.3:a:php:php:8.1:*:*:*:*:*:*:*"
        );
        assert_eq!(
            build_cpe(&tech("WordPress", Some("6.4"))).unwrap(),
            "cpe:2.3:a:wordpress:wordpress:6.4:*:*:*:*:*:*:*"
        );
    }

    #[test]
    fn test_build_cpe_requires_version_and_known_mapping() {
        assert!(build_cpe(&tech("nginx", None)).is_none());
        assert!(build_cpe(&tech("UnknownThing", Some("1.0"))).is_none());
    }

    #[test]
    fn test_explain_cpe_applicability_supports_aliases_and_failures() {
        let applicable = explain_cpe_applicability(&tech("Apache httpd", Some("2.4.51")));
        assert_eq!(applicable.status, ApplicabilityStatus::Applicable);
        assert!(applicable.reason.contains("maps to CPE"));

        let missing = explain_cpe_applicability(&tech("nginx", None));
        assert_eq!(missing.status, ApplicabilityStatus::MissingVersion);

        let unknown = explain_cpe_applicability(&tech("UnknownThing", Some("1.0")));
        assert_eq!(unknown.status, ApplicabilityStatus::UnknownProductMapping);
    }
}

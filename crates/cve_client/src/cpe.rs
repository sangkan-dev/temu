use std::collections::HashMap;
use std::sync::LazyLock;

use fingerprint::TechStack;

static CPE_MAP: LazyLock<HashMap<&'static str, (&'static str, &'static str)>> =
    LazyLock::new(|| {
        HashMap::from([
            ("nginx", ("f5", "nginx")),
            ("apache", ("apache", "http_server")),
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
            ("express", ("expressjs", "express")),
            ("django", ("djangoproject", "django")),
            ("ruby on rails", ("rubyonrails", "rails")),
            ("spring", ("vmware", "spring_framework")),
            ("tomcat", ("apache", "tomcat")),
            ("openssl", ("openssl", "openssl")),
            ("mysql", ("oracle", "mysql")),
            ("mariadb", ("mariadb", "mariadb")),
            ("postgresql", ("postgresql", "postgresql")),
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
    let version = tech.version.as_deref()?;
    if version.trim().is_empty() {
        return None;
    }

    let key = tech.name.to_lowercase();
    let (vendor, product) = CPE_MAP.get(key.as_str())?;

    Some(format!(
        "cpe:2.3:a:{vendor}:{product}:{}:*:*:*:*:*:*:*",
        sanitize_version(version)
    ))
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
}

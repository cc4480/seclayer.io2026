import { Template } from "./templateEngine.js";

// Starter detection pack. Each template confirms the finding by matching the
// response BODY signature and excluding SPA HTML fallbacks (negative matcher),
// so a single-page app that returns index.html for every path is never flagged.
// Grow coverage by adding entries here — no engine changes required.
//
// Paths already covered by the scanner's signature probes (/.env, /.git/config,
// /.git/HEAD, /phpinfo.php, /.aws/credentials, /config.json) are intentionally
// omitted to avoid duplicate findings.

const NOT_HTML = { type: "word" as const, words: ["<!doctype", "<html", "<head", "<body"], negative: true };

const RAW_TEMPLATES: Template[] = [
  {
    id: "spring-actuator-env",
    name: "Spring Boot Actuator /env Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "The Spring Boot Actuator env endpoint is publicly reachable and leaks application configuration, environment variables, and frequently database credentials.",
    fix: "Restrict actuator endpoints to an internal management port and require authentication (management.endpoints.web.exposure.include / Spring Security).",
    requests: [
      {
        path: "/actuator/env",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["propertySources", "systemEnvironment", "systemProperties"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "spring-actuator-health",
    name: "Spring Boot Actuator /health Exposed",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "The Spring Boot Actuator health endpoint is publicly reachable, disclosing internal component status and aiding fingerprinting.",
    fix: "Limit actuator exposure and authenticate management endpoints.",
    requests: [
      {
        path: "/actuator/health",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"status":"UP"', '"status": "UP"'], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "dockerfile-exposed",
    name: "Dockerfile Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "A Dockerfile is served from the web root, revealing base images, build steps, and sometimes embedded secrets or internal paths.",
    fix: "Remove build artifacts from the public web root; serve only the built application.",
    requests: [
      {
        path: "/Dockerfile",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: "^\\s*FROM\\s+\\S+" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "docker-compose-exposed",
    name: "docker-compose.yml Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A docker-compose file is publicly accessible, exposing service topology, environment variables, ports, and often credentials.",
    fix: "Remove infrastructure manifests from the public web root.",
    requests: [
      {
        path: "/docker-compose.yml",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["services:", "image:", "version:"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "package-json-exposed",
    name: "package.json Exposed",
    severity: "low",
    category: "SCA",
    confidence: "high",
    description:
      "package.json is served from the web root, disclosing the full dependency list and versions that attackers can correlate against known CVEs.",
    fix: "Do not serve package manifests from the public web root.",
    requests: [
      {
        path: "/package.json",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"dependencies"', '"devDependencies"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "env-backup-exposed",
    name: "Environment File Backup Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A backup copy of an environment file (.env.bak / .env.save / .env.old) is publicly readable and typically contains live credentials.",
    fix: "Remove backup files from the web root and rotate any exposed secrets immediately.",
    requests: [
      {
        path: "/.env.bak",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: "^[A-Z][A-Z0-9_]*\\s*=" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/.env.save",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: "^[A-Z][A-Z0-9_]*\\s*=" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "wp-config-backup",
    name: "WordPress wp-config Backup Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A backup of wp-config.php is publicly readable, exposing database credentials and WordPress authentication keys.",
    fix: "Delete configuration backups from the web root and rotate the exposed database credentials and salts.",
    requests: [
      {
        path: "/wp-config.php.bak",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["DB_PASSWORD", "DB_NAME"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "phpmyadmin-exposed",
    name: "phpMyAdmin Panel Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "A phpMyAdmin login panel is publicly reachable, providing a brute-force surface directly onto the database.",
    fix: "Restrict phpMyAdmin to a VPN/allow-list and enforce strong authentication.",
    requests: [
      {
        path: "/phpmyadmin/",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["phpMyAdmin", "pma_username"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "adminer-exposed",
    name: "Adminer Database Tool Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "Adminer is publicly reachable, exposing a database administration login to the internet.",
    fix: "Remove Adminer from production or restrict it behind authentication and network controls.",
    requests: [
      {
        path: "/adminer.php",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Adminer", "Login - Adminer"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "apache-server-status",
    name: "Apache mod_status Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "The Apache server-status page is publicly reachable, leaking active request URLs, client IPs, and server internals.",
    fix: 'Restrict <Location /server-status> to localhost or trusted IPs.',
    requests: [
      {
        path: "/server-status",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Apache Server Status", "Server uptime"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "laravel-telescope",
    name: "Laravel Telescope Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "Laravel Telescope is reachable in production, exposing requests, queries, mail, and sensitive runtime data.",
    fix: "Disable Telescope in production or gate it behind the Telescope authorization gate.",
    requests: [
      {
        path: "/telescope/requests",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Telescope", "Laravel"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "swagger-ui-exposed",
    name: "Swagger UI Exposed",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "Interactive Swagger/OpenAPI UI is publicly reachable, documenting the full API surface for attackers.",
    fix: "Restrict API documentation to authenticated/internal users in production.",
    requests: [
      {
        path: "/swagger-ui/index.html",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Swagger UI", "swagger-ui"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- Source / VCS / config file exposure ---
  {
    id: "git-credentials-exposed",
    name: "Git Credentials File Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A .git-credentials file is publicly readable and embeds credentials directly inside repository URLs.",
    fix: "Remove the file from the web root and rotate the exposed credentials.",
    requests: [
      {
        path: "/.git-credentials",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: "https?://[^:/]+:[^@]+@" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "web-config-exposed",
    name: "IIS web.config Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "An ASP.NET/IIS web.config is publicly readable, often exposing connection strings, machine keys, and app settings.",
    fix: "Block direct access to web.config and rotate any exposed connection strings or machine keys.",
    requests: [
      {
        path: "/web.config",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["<configuration", "<system.webServer", "<connectionStrings"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "webinf-web-xml-exposed",
    name: "Java WEB-INF/web.xml Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "The Java deployment descriptor WEB-INF/web.xml is publicly readable, disclosing servlet mappings, parameters, and internal structure.",
    fix: "Ensure the servlet container denies direct access to /WEB-INF/.",
    requests: [
      {
        path: "/WEB-INF/web.xml",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["<web-app", "<servlet"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "htaccess-exposed",
    name: "Apache .htaccess Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "An .htaccess file is publicly readable, revealing rewrite rules, access controls, and internal path structure.",
    fix: "Configure the server to deny access to files beginning with a dot.",
    requests: [
      {
        path: "/.htaccess",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["RewriteEngine", "RewriteRule", "<IfModule", "Order allow"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "htpasswd-exposed",
    name: "Apache .htpasswd Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "An .htpasswd file is publicly readable, exposing usernames and password hashes for offline cracking.",
    fix: "Deny web access to .htpasswd and rotate the affected credentials.",
    requests: [
      {
        path: "/.htpasswd",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: ":\\$(apr1|2[aby]|1|5|6)\\$" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- Environment variants & database dumps ---
  {
    id: "env-production-exposed",
    name: "Production Environment File Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A production environment file (.env.production / .env.local) is publicly readable and typically contains live secrets.",
    fix: "Remove the file from the web root and rotate every exposed secret.",
    requests: [
      {
        path: "/.env.production",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: "^[A-Z][A-Z0-9_]*\\s*=" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/.env.local",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: "^[A-Z][A-Z0-9_]*\\s*=" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "sql-dump-exposed",
    name: "Database Dump Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A SQL database dump is publicly downloadable, exposing complete schema and data including potentially credentials and PII.",
    fix: "Remove database dumps from the web root immediately and assess for data exposure.",
    requests: [
      {
        path: "/backup.sql",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "MySQL dump", "PostgreSQL database dump"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/database.sql",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "MySQL dump"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/dump.sql",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "MySQL dump"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "backup-archive-exposed",
    name: "Backup Archive Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A site/source backup archive is publicly downloadable from the web root, frequently containing source code and secrets.",
    fix: "Remove archive files from the web root and store backups outside the document root.",
    requests: [
      {
        path: "/backup.zip",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", part: "header", words: ["application/zip", "application/x-zip", "application/octet-stream"], condition: "or" },
        ],
        matchersCondition: "and",
      },
      {
        path: "/backup.tar.gz",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", part: "header", words: ["application/gzip", "application/x-gzip", "application/x-tar", "application/octet-stream"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- Deployment / CI / package manifests ---
  {
    id: "vscode-sftp-exposed",
    name: "VS Code SFTP Config Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A .vscode/sftp.json deployment config is publicly readable and commonly contains SFTP/SSH host credentials.",
    fix: "Remove the file from the web root and rotate the exposed deployment credentials.",
    requests: [
      {
        path: "/.vscode/sftp.json",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"password"', '"privateKeyPath"', '"host"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "gitlab-ci-exposed",
    name: "GitLab CI Config Exposed",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "A .gitlab-ci.yml is publicly readable, disclosing pipeline structure and occasionally embedded variables.",
    fix: "Avoid serving CI configuration from the web root.",
    requests: [
      {
        path: "/.gitlab-ci.yml",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["stages:", "script:", "image:"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "composer-json-exposed",
    name: "composer.json Exposed",
    severity: "low",
    category: "SCA",
    confidence: "high",
    description:
      "composer.json is served from the web root, disclosing the PHP dependency list and versions for CVE correlation.",
    fix: "Do not serve dependency manifests from the public web root.",
    requests: [
      {
        path: "/composer.json",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"require"', '"require-dev"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "composer-lock-exposed",
    name: "composer.lock Exposed",
    severity: "low",
    category: "SCA",
    confidence: "high",
    description:
      "composer.lock is served from the web root, disclosing exact PHP dependency versions for CVE correlation.",
    fix: "Do not serve lockfiles from the public web root.",
    requests: [
      {
        path: "/composer.lock",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"packages"', '"content-hash"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- Framework actuators / dev tooling exposed in production ---
  {
    id: "jolokia-exposed",
    name: "Jolokia JMX Endpoint Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A Jolokia endpoint exposes JMX over HTTP, allowing enumeration (and sometimes invocation) of MBeans — a known RCE vector.",
    fix: "Disable Jolokia in production or restrict it to authenticated internal access.",
    requests: [
      {
        path: "/jolokia/list",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["jolokia", '"agent"', '"request"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "actuator-configprops-exposed",
    name: "Spring Actuator /configprops Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "The Spring Actuator configprops endpoint is reachable, disclosing bound configuration properties and infrastructure details.",
    fix: "Restrict actuator exposure and require authentication on management endpoints.",
    requests: [
      {
        path: "/actuator/configprops",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["contexts", "beans", "configProps", "prefix"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "symfony-profiler-exposed",
    name: "Symfony Profiler Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "The Symfony web profiler is reachable in production, exposing requests, queries, sessions, and configuration.",
    fix: "Disable the profiler/web toolbar in the production environment.",
    requests: [
      {
        path: "/_profiler",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Symfony Profiler", "sf-toolbar", "WebProfilerBundle"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "rails-info-exposed",
    name: "Rails Application Info Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "The Rails /rails/info endpoints are reachable, indicating development mode in production and disclosing routes and versions.",
    fix: "Run Rails in the production environment and ensure detailed error/info pages are disabled.",
    requests: [
      {
        path: "/rails/info/properties",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Ruby version", "Rails version", "Middleware"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "wp-user-enumeration",
    name: "WordPress REST User Enumeration",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "The WordPress REST users endpoint returns the list of accounts, enabling username enumeration for targeted brute-force.",
    fix: "Restrict or disable the wp/v2/users REST endpoint for unauthenticated requests.",
    requests: [
      {
        path: "/wp-json/wp/v2/users",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"slug"', '"name"'], condition: "and" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "solr-admin-exposed",
    name: "Apache Solr Admin Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "The Apache Solr admin interface is publicly reachable, exposing core management and a known RCE surface.",
    fix: "Restrict the Solr admin UI/API to trusted internal networks.",
    requests: [
      {
        path: "/solr/",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Solr Admin", "Apache SOLR", "solr-admin"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- API specs / GraphQL tooling ---
  {
    id: "openapi-spec-exposed",
    name: "OpenAPI/Swagger Spec Exposed",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "A machine-readable OpenAPI/Swagger specification is publicly reachable, fully documenting the API surface for attackers.",
    fix: "Restrict API specifications to authenticated/internal consumers in production.",
    requests: [
      {
        path: "/openapi.json",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"openapi"', '"swagger"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/v2/api-docs",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"swagger"', '"openapi"', '"paths"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "graphiql-exposed",
    name: "GraphiQL / GraphQL Playground Exposed",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "An interactive GraphQL IDE is publicly reachable, easing schema exploration and query crafting against the API.",
    fix: "Disable GraphiQL/Playground in production.",
    requests: [
      {
        path: "/graphiql",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["graphiql", "GraphQL Playground", "GraphiQL"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- Exposed datastores / services over HTTP ---
  {
    id: "elasticsearch-exposed",
    name: "Elasticsearch Cluster Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "An Elasticsearch HTTP API is publicly reachable, allowing index enumeration and unauthenticated data access.",
    fix: "Bind Elasticsearch to an internal interface and require authentication (e.g. X-Pack/security).",
    requests: [
      {
        path: "/_cluster/health",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"cluster_name"', '"number_of_nodes"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "couchdb-exposed",
    name: "Apache CouchDB Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A CouchDB instance/admin UI is publicly reachable, exposing databases to unauthenticated access.",
    fix: "Restrict CouchDB to internal networks and configure an admin account.",
    requests: [
      {
        path: "/_utils/",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Fauxton", "couchdb"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "kubernetes-api-exposed",
    name: "Kubernetes API Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A Kubernetes API server version endpoint is publicly reachable, indicating an exposed control plane.",
    fix: "Restrict the Kubernetes API to trusted networks and disable anonymous auth.",
    requests: [
      {
        path: "/version",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"gitVersion"', '"goVersion"', '"compiler"'], condition: "and" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "rabbitmq-management-exposed",
    name: "RabbitMQ Management API Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "The RabbitMQ management API is publicly reachable, disclosing broker version and topology.",
    fix: "Restrict the RabbitMQ management plugin to internal access.",
    requests: [
      {
        path: "/api/overview",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["rabbitmq_version", "management_version"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- Monitoring / observability dashboards ---
  {
    id: "prometheus-metrics-exposed",
    name: "Prometheus Metrics Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "A Prometheus metrics endpoint is publicly reachable, leaking internal performance, hostnames, and operational detail.",
    fix: "Restrict /metrics to internal scrapers or require authentication.",
    requests: [
      {
        path: "/metrics",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["# HELP", "# TYPE"], condition: "and" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "grafana-exposed",
    name: "Grafana Instance Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "A Grafana dashboard login is publicly reachable, providing a brute-force surface and (on old versions) known exploits.",
    fix: "Place Grafana behind SSO/VPN and keep it patched.",
    requests: [
      {
        path: "/login",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Grafana", "grafana-app"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "kibana-exposed",
    name: "Kibana Instance Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "A Kibana interface is publicly reachable, exposing dashboards over the underlying Elasticsearch data.",
    fix: "Restrict Kibana to internal/authenticated access.",
    requests: [
      {
        path: "/app/kibana",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["kbn-injected-metadata", "kibana"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- Cloud / key material ---
  {
    id: "gcp-service-account-exposed",
    name: "GCP Service Account Key Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A Google Cloud service-account key file is publicly readable, granting programmatic access to cloud resources.",
    fix: "Remove the key from the web root and revoke/rotate the service-account key immediately.",
    requests: [
      {
        path: "/service-account.json",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"private_key"', '"client_email"'], condition: "and" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/credentials.json",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"private_key"', '"client_email"'], condition: "and" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "ssh-private-key-exposed",
    name: "SSH Private Key Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "An SSH private key is publicly downloadable from the web root, enabling direct server access.",
    fix: "Remove the key from the web root and rotate it (and any authorized_keys it maps to) immediately.",
    requests: [
      {
        path: "/.ssh/id_rsa",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["PRIVATE KEY-----"] },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/id_rsa",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["PRIVATE KEY-----"] },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "npmrc-token-exposed",
    name: "npm Auth Token (.npmrc) Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "An .npmrc containing an npm auth token is publicly readable, allowing package publish/install under that account.",
    fix: "Remove .npmrc from the web root and revoke the npm token.",
    requests: [
      {
        path: "/.npmrc",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["_authToken", "_auth="], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- CMS-specific exposures ---
  {
    id: "wp-debug-log-exposed",
    name: "WordPress debug.log Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "WordPress debug logging is enabled and the log is publicly readable, leaking stack traces, paths, and sometimes secrets.",
    fix: "Disable WP_DEBUG_LOG in production and remove the exposed log file.",
    requests: [
      {
        path: "/wp-content/debug.log",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["PHP Notice", "PHP Warning", "PHP Fatal error", "WordPress database error", "Stack trace"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "wp-xmlrpc-enabled",
    name: "WordPress XML-RPC Enabled",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "xmlrpc.php is enabled, providing an amplification surface for credential brute-force and pingback-based DDoS.",
    fix: "Disable XML-RPC if unused, or restrict and rate-limit it.",
    requests: [
      {
        path: "/xmlrpc.php",
        matchers: [
          { type: "status", status: [200, 405] },
          { type: "word", words: ["XML-RPC server accepts POST requests only"] },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "drupal-changelog-exposed",
    name: "Drupal Version Disclosed (CHANGELOG.txt)",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "Drupal's CHANGELOG.txt is publicly readable, disclosing the exact core version for targeted exploitation.",
    fix: "Remove or block access to CHANGELOG.txt and keep core patched.",
    requests: [
      {
        path: "/CHANGELOG.txt",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Drupal "] },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/core/CHANGELOG.txt",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Drupal "] },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "joomla-config-backup-exposed",
    name: "Joomla configuration.php Backup Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A backup of Joomla's configuration.php is publicly readable, exposing database credentials and secrets.",
    fix: "Remove the backup from the web root and rotate the exposed credentials.",
    requests: [
      {
        path: "/configuration.php~",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["JConfig", "public $password", "public $db"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- Dev / CI tooling exposed ---
  {
    id: "laravel-debugbar-exposed",
    name: "Laravel Debugbar Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "Laravel Debugbar assets are reachable, indicating debug mode in production and leaking queries/requests.",
    fix: "Disable Debugbar and set APP_DEBUG=false in production.",
    requests: [
      {
        path: "/_debugbar/open",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["phpdebugbar", "PhpDebugBar"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "jenkins-exposed",
    name: "Jenkins Login Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A Jenkins CI login is publicly reachable, presenting a high-value RCE target if misconfigured or unpatched.",
    fix: "Place Jenkins behind a VPN/SSO and keep it updated; never expose it directly.",
    requests: [
      {
        path: "/login",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Jenkins", "j_username"], condition: "and" },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "server-log-exposed",
    name: "Server Log File Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "A server/application log file is publicly readable, leaking stack traces, internal paths, and request details.",
    fix: "Store logs outside the web root and deny direct access to log files.",
    requests: [
      {
        path: "/error_log",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["PHP Fatal error", "PHP Warning", "[error]", "Stack trace"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/logs/error.log",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["PHP Fatal error", "PHP Warning", "[error]", "Stack trace"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- Dangling-resource / subdomain takeover (service "not found" fingerprints) ---
  {
    id: "subdomain-takeover",
    name: "Potential Subdomain Takeover",
    severity: "high",
    category: "EASM",
    confidence: "high",
    description:
      "The host responds with a third-party service's 'unclaimed resource' page, indicating a dangling DNS record an attacker could claim to take over the (sub)domain.",
    fix: "Remove the dangling DNS record or re-claim the resource on the referenced provider.",
    requests: [
      {
        path: "/",
        matchers: [
          {
            type: "word",
            words: [
              "There isn't a GitHub Pages site here.",
              "herokucdn.com",
              "NoSuchBucket",
              "Sorry, this shop is currently unavailable",
              "Fastly error: unknown domain",
              "The gods are wise, but do not know of the site which you seek.",
              "is not configured for an account",
              "Whatever you were looking for doesn't currently exist at this address",
            ],
            condition: "or",
          },
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- Cloud storage / directory listing ---
  {
    id: "s3-bucket-listing",
    name: "S3 Bucket Listing Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "The endpoint returns an S3 XML bucket listing, exposing object keys (and potentially their contents) to anonymous users.",
    fix: "Disable public list permissions on the bucket and apply a restrictive bucket policy.",
    requests: [
      {
        path: "/",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["<ListBucketResult"] },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "open-directory-listing",
    name: "Open Directory Listing Enabled",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "The server returns an auto-generated directory index, exposing the file listing of the document root or a subdirectory.",
    fix: "Disable automatic directory indexing (Apache Options -Indexes / nginx autoindex off).",
    requests: [
      {
        path: "/",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["<title>Index of /", "[To Parent Directory]", "Directory listing for /"], condition: "or" },
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- Infrastructure / cloud credential files ---
  {
    id: "kubeconfig-exposed",
    name: "Kubeconfig Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A kubeconfig file is publicly readable, embedding cluster endpoints and client certificate/token credentials.",
    fix: "Remove the file from the web root and rotate the embedded cluster credentials.",
    requests: [
      {
        path: "/.kube/config",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["client-certificate-data", "client-key-data", "current-context:"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "terraform-state-exposed",
    name: "Terraform State Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "A Terraform state file is publicly readable; state frequently contains plaintext secrets, keys, and full infrastructure detail.",
    fix: "Remove state from the web root, use a secured remote backend, and rotate any exposed secrets.",
    requests: [
      {
        path: "/terraform.tfstate",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"terraform_version"', '"lineage"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/.terraform/terraform.tfstate",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"terraform_version"', '"lineage"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "docker-config-exposed",
    name: "Docker Registry Config Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A Docker client config is publicly readable, exposing base64-encoded registry credentials.",
    fix: "Remove the file from the web root and rotate the registry credentials.",
    requests: [
      {
        path: "/.docker/config.json",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"auths"', '"auth"'], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/.dockercfg",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ['"auth"', "https://index.docker.io"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "netrc-exposed",
    name: ".netrc Credentials Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "A .netrc file is publicly readable, exposing machine login/password pairs used for automated authentication.",
    fix: "Remove .netrc from the web root and rotate the exposed credentials.",
    requests: [
      {
        path: "/.netrc",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: "machine\\s+\\S+\\s+(login|password)\\s+\\S+" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "aws-config-exposed",
    name: "AWS CLI Config Exposed",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "An AWS CLI config file is publicly readable, disclosing profiles, regions, and role/account references.",
    fix: "Remove the file from the web root.",
    requests: [
      {
        path: "/.aws/config",
        matchers: [
          { type: "status", status: [200] },
          { type: "regex", regex: "\\[(default|profile )" },
          { type: "word", words: ["region", "role_arn", "output"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },

  // --- Exposed admin tooling / CMS config backups / artifacts ---
  {
    id: "tomcat-manager-exposed",
    name: "Apache Tomcat Manager Exposed",
    severity: "high",
    category: "DAST",
    confidence: "high",
    description:
      "The Tomcat Web Application Manager is reachable, a high-value target for deploying a malicious WAR (RCE) if credentials are weak.",
    fix: "Restrict the manager app to trusted networks and use strong, unique credentials.",
    requests: [
      {
        path: "/manager/html",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Tomcat Web Application Manager"] },
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "wp-config-save-exposed",
    name: "WordPress wp-config Editor Backup Exposed",
    severity: "critical",
    category: "DAST",
    confidence: "high",
    description:
      "An editor/temp backup of wp-config.php is publicly readable, exposing database credentials and WordPress salts.",
    fix: "Delete the backup, block dotted/tilde temp files, and rotate the exposed credentials.",
    requests: [
      {
        path: "/wp-config.php.save",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["DB_PASSWORD", "DB_NAME"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
      {
        path: "/wp-config.php~",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["DB_PASSWORD", "DB_NAME"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "laravel-log-exposed",
    name: "Laravel Log File Exposed",
    severity: "medium",
    category: "DAST",
    confidence: "high",
    description:
      "A Laravel application log is publicly readable, leaking stack traces, queries, and frequently secrets in error context.",
    fix: "Store logs outside the web root and deny direct access to the storage directory.",
    requests: [
      {
        path: "/storage/logs/laravel.log",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["production.ERROR", "local.ERROR", "Stack trace", "stacktrace"], condition: "or" },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
  {
    id: "dsstore-exposed",
    name: ".DS_Store File Exposed",
    severity: "low",
    category: "DAST",
    confidence: "high",
    description:
      "A macOS .DS_Store file is publicly readable, enabling reconstruction of the directory's file names.",
    fix: "Remove .DS_Store files from the web root and add them to your ignore rules.",
    requests: [
      {
        path: "/.DS_Store",
        matchers: [
          { type: "status", status: [200] },
          { type: "word", words: ["Bud1"] },
          NOT_HTML,
        ],
        matchersCondition: "and",
      },
    ],
  },
];

// Framework-coupled templates only run when that stack is detected (see
// techprofile.ts). Everything else is generic and always runs.
const TEMPLATE_TAGS: Record<string, string[]> = {
  "spring-actuator-env": ["spring"],
  "spring-actuator-health": ["spring"],
  "actuator-configprops-exposed": ["spring"],
  "jolokia-exposed": ["java"],
  "webinf-web-xml-exposed": ["java"],
  "tomcat-manager-exposed": ["tomcat"],
  "wp-config-backup": ["wordpress"],
  "wp-config-save-exposed": ["wordpress"],
  "wp-debug-log-exposed": ["wordpress"],
  "wp-xmlrpc-enabled": ["wordpress"],
  "wp-user-enumeration": ["wordpress"],
  "laravel-telescope": ["laravel"],
  "laravel-debugbar-exposed": ["laravel"],
  "laravel-log-exposed": ["laravel"],
  "symfony-profiler-exposed": ["symfony"],
  "rails-info-exposed": ["rails"],
  "drupal-changelog-exposed": ["drupal"],
  "joomla-config-backup-exposed": ["joomla"],
  "composer-json-exposed": ["php"],
  "composer-lock-exposed": ["php"],
  "web-config-exposed": ["aspnet"],
};

export const TEMPLATES: Template[] = RAW_TEMPLATES.map((t) => ({
  ...t,
  tags: TEMPLATE_TAGS[t.id],
}));

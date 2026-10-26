"""
Configuration, wordlists, payloads, and signatures for PyStalker.
"""
import os

OUTPUT_DIR = "stalker_results"
SCREENSHOTS_DIR = os.path.join(OUTPUT_DIR, "screenshots")

DEFAULT_THREADS = 25
DEFAULT_TIMEOUT = 8

# User-Agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
]

CUSTOM_HEADERS = {
    "User-Agent": USER_AGENTS[0],
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,pt-BR;q=0.8,pt;q=0.7",
    "Sec-Ch-Ua": '"Chromium";v="122", "Not(A:Brand";v="24"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Linux"',
    "Upgrade-Insecure-Requests": "1"
}

API_KEYS = {
    "SECURITYTRAILS": os.getenv("SECURITYTRAILS_API_KEY", ""),
    "SHODAN": os.getenv("SHODAN_API_KEY", ""),
    "GOOGLE_API_KEY": os.getenv("GOOGLE_API_KEY", ""),
    "GOOGLE_CSE_ID": os.getenv("GOOGLE_CSE_ID", ""),
    "VIRUSTOTAL": os.getenv("VT_API_KEY", ""),
    "GITHUB": os.getenv("GITHUB_TOKEN", "")
}

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "admin", "portal", "api", 
    "test", "dev", "staging", "blog", "app", "mobile", "secure", 
    "vpn", "crm", "shop", "cdn", "login", "auth", "oauth", "sso",
    "m", "web", "static", "assets", "beta", "support", "dashboard",
    "corp", "gateway", "internal", "intranet", "monitor", "grafana",
    "kibana", "elastic", "jenkins", "gitlab", "git", "ci", "stage",
    "prod", "uat", "demo", "doc", "docs", "panel", "cpanel", "whm"
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/wp-admin", "/wp-login.php", "/administrator", 
    "/manager", "/login", "/auth", "/signin", "/controlpanel",
    "/adminpanel", "/cpanel", "/secure", "/console", "/backoffice",
    "/system", "/user", "/account", "/dashboard", "/root", "/portal/admin"
]

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.gitignore", "/.svn/entries",
    "/.aws/credentials", "/.aws/config",
    "/.htaccess", "/web.config",
    "/debug.log", "/error.log", "/access.log", "/storage/logs/laravel.log",
    "/phpinfo.php", "/info.php",
    "/.well-known/security.txt",
    "/config.php", "/configuration.php", "/config.json", "/settings.json",
    "/server-status", "/server-info",
    "/backup.zip", "/dump.sql", "/backup.sql", "/database.sql", "/backup.tar.gz",
    "/credentials.json", "/id_rsa", "/id_rsa.pub", "/.npmrc", "/.dockercfg",
    "/docker-compose.yml", "/Dockerfile", "/.bash_history",
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json", "/api-docs",
    "/actuator/health", "/actuator/env", "/actuator"
]

BACKUP_EXTENSIONS = [".bak", ".old", ".tmp", ".swp", ".save", ".orig", ".copy", "~"]

LOGIN_INDICATORS = [
    "login", "sign in", "username", "password", "email", "log in", 
    "signin", "auth", "authentication", "credentials", "acessar conta",
    "entrar", "senha", "usuário", "user", "pass", "pwd"
]

TOP_PORTS = [
    80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 8081,
    21, 22, 25, 3306, 5432, 6379, 27017
]

INTERESTING_PARAMS = [
    "id", "user", "account", "file", "path", "dir", "document",
    "url", "redirect", "next", "return", "dest", "view",
    "cmd", "exec", "query", "search", "token", "key", "api_key"
]

# Signatures for Subdomain Takeovers
TAKEOVER_FINGERPRINTS = {
    "GitHub Pages": {
        "cname": ["github.io"],
        "response": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"]
    },
    "Amazon S3": {
        "cname": ["s3.amazonaws.com", "s3-website"],
        "response": ["NoSuchBucket", "The specified bucket does not exist"]
    },
    "Heroku": {
        "cname": ["herokuapp.com", "herokussl.com"],
        "response": ["No such app", "Heroku | No such app", "item not found"]
    },
    "Shopify": {
        "cname": ["myshopify.com"],
        "response": ["Sorry, this shop is currently unavailable"]
    },
    "Tumblr": {
        "cname": ["domains.tumblr.com"],
        "response": ["Whatever you were looking for doesn't seem to exist at this address"]
    },
    "WordPress": {
        "cname": ["wordpress.com"],
        "response": ["Do you want to register"]
    },
    "Zendesk": {
        "cname": ["zendesk.com"],
        "response": ["Help Center Closed"]
    },
    "Fastly": {
        "cname": ["fastly.net"],
        "response": ["Fastly error: unknown domain"]
    },
    "Ghost": {
        "cname": ["ghost.io"],
        "response": ["The thing you were looking for is no longer here"]
    },
    "Surge.sh": {
        "cname": ["surge.sh"],
        "response": ["project not found"]
    },
    "Bitbucket": {
        "cname": ["bitbucket.io"],
        "response": ["Repository not found"]
    },
    "Cargo Collective": {
        "cname": ["cargocollective.com"],
        "response": ["If you're moving with Cargo, you can make your site private"]
    }
}

# WAF Detection Signatures
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server: cloudflare", "__cfduid"],
        "body": ["Attention Required! | Cloudflare", "cloudflare-nginx"]
    },
    "AWS WAF / CloudFront": {
        "headers": ["x-amz-cf-id", "x-amzn-requestid", "server: cloudfront", "x-amz-id-2"],
        "body": ["Generated by cloudfront (CloudFront)"]
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-origin-hop", "server: akamai"],
        "body": ["Access Denied - Akamai"]
    },
    "Imperva / Incapsula": {
        "headers": ["x-cdn: incapsula", "x-iinfo", "incap_ses"],
        "body": ["Incapsula incident ID", "_Incapsula_Resource"]
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache", "server: sucuri/cloudproxy"],
        "body": ["Access Denied - Sucuri Website Firewall"]
    },
    "F5 BIG-IP": {
        "headers": ["bigipserver", "x-cnection: close", "server: big-ip"],
        "body": ["The requested URL was rejected. Please consult with your administrator."]
    },
    "Fastly": {
        "headers": ["x-fastly-request-id", "fastly-debug-digest"],
        "body": []
    }
}

# Payloads for fuzzing & vulnerability checks
PAYLOADS = {
    "XSS": {
        "generic": [
            '"><script>alert("PyStalker-XSS")</script>',
            '"><img src=x onerror=alert("PyStalker-XSS")>',
            'javascript:alert("PyStalker-XSS")',
            "'-alert(1)-'",
            '"><svg/onload=alert("PyStalker-XSS")>'
        ],
        "php": [
            '"><script>alert(1)</script>',
            '${alert(1)}'
        ],
        "nodejs": [
            "{{= 'XSS' }}",
            "<%= 'XSS' %>"
        ],
        "nextjs": [
            "{`${alert('XSS')}`}",
            "{alert('XSS')}"
        ],
        "angular": [
            "{{constructor.constructor('alert(1)')()}}"
        ]
    },
    "SQLi": {
        "generic": [
            "' OR '1'='1",
            "' OR 1=1--",
            '" OR ""="',
            "' OR 1=1#"
        ],
        "mysql": [
            "' OR SLEEP(5)--"
        ],
        "mssql": [
            "' WAITFOR DELAY '0:0:5'--"
        ]
    }
}

# Vulnerability Regex Signatures
VULN_SIGNATURES = {
    "SQL_INJECTION": r"SQL syntax.*MySQL|Warning.*mysql_|unclosed quotation mark|syntax error in query|PostgreSQL.*ERROR|ORA-[0-9]{4,5}|Microsoft OLE DB Provider for ODBC Drivers",
    "XSS": r"<script>alert\(|onerror=.?alert\(|javascript:|alert\(|svg/onload=alert\(",
    "RCE": r"sh:.*command not found|/bin/bash|www.shell.com|nc -lvp|daemon:x:2:",
    "LFI": r"root:x:0:0:|root:.*:/bin/bash|Failed opening.*for inclusion|\[boot loader\]",
    "DEBUG_MODE": r"DEBUG_MODE.*true|APP_DEBUG.*true|stack trace:|Whoops\! There was an error|Traceback \(most recent call last\):",
    "CREDS_LEAK": r"(?:api[_-]?key|api[_-]?secret|aws_access_key_id|aws_secret_access_key|database_url|db_password|jwt[_-]?secret|BEGIN RSA PRIVATE KEY)[\s:='\"]+[\w\-\.\/]{10,}",
    "CORS_MISCONFIG": r"Access-Control-Allow-Origin:\s*\*"
}

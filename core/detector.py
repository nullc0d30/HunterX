# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# All Rights Reserved.
#
# HunterX — AI-Assisted Vulnerability Hunter
import re
from typing import List

SIGNATURES: List[tuple] = [
    # === LFI / Path Traversal ===
    (r"root:x:0:0:", "Critical - LFI (/etc/passwd)"),
    (r"\[fonts\]|\[extension\]", "High - LFI (win.ini)"),
    (r"boot\.ini", "Medium - LFI (boot.ini)"),
    (r"drivers\\etc\\hosts", "High - LFI (Windows hosts)"),
    (r"\[Mail\]|\[MCI\]", "Medium - LFI (win.ini section)"),
    (r"mysql\.conf|my\.cnf", "High - LFI (DB config leak)"),
    (r"wp-config\.php", "Critical - LFI (WordPress config)"),
    (r"DB_HOST|DB_NAME|DB_USER|DB_PASSWORD", "Critical - LFI (DB credentials)"),
    (r"-----BEGIN RSA PRIVATE KEY-----", "Critical - LFI (Private key leak)"),
    (r"-----BEGIN OPENSSH PRIVATE KEY-----", "Critical - LFI (SSH key leak)"),
    (r"aws_access_key_id|aws_secret_access_key", "Critical - LFI (AWS credentials)"),
    (r"bucket_name|s3\.amazonaws\.com", "Medium - LFI (S3 reference)"),
    (r"api_key|api_secret|apikey", "High - LFI (API key leak)"),
    (r"JWT_TOKEN|jwt_token", "Medium - LFI (JWT token)"),
    (r"oauth_token|oauth_secret", "High - LFI (OAuth secret)"),

    # === RCE ===
    (r"uid=\d+\(root\)", "Critical - RCE (id as root)"),
    (r"uid=\d+\([\w]+\)", "High - RCE (id output)"),
    (r"Windows IP Configuration", "Critical - RCE (ipconfig)"),
    (r"uid=\d+", "High - RCE (user id)"),
    (r"gid=\d+", "Medium - RCE (group id)"),
    (r"groups?=\d+", "Medium - RCE (groups)"),
    (r"Linux \S+ \d+\.\d+\.\d+", "High - RCE (uname output)"),
    (r"www-data|xfs|nobody", "Medium - RCE (user context)"),
    (r"PHP_VERSION|SERVER_SOFTWARE", "Medium - RCE (phpinfo)"),
    (r"HTTP_HOST|SERVER_ADDR", "Low - RCE (phpinfo leak)"),
    (r"\$PWD|\$HOME|\$USER", "Medium - RCE (env variable leak)"),
    (r"total \d+\ndrwxr-xr-x", "Critical - RCE (directory listing)"),
    (r"-rw-r--r--\s+\d+\s+\w+", "High - RCE (file listing)"),
    (r"\d+ bytes? from ", "Medium - RCE (ping output)"),
    (r"bytes? from ", "Medium - RCE (network command)"),
    (r"TTL=\d+", "Medium - RCE (ping TTL)"),

    # === SQL Injection ===
    (r"SQL syntax.*MySQL", "High - SQLi (MySQL error)"),
    (r"SQL syntax", "Medium - SQLi (generic syntax error)"),
    (r"mysql_fetch_array|mysql_fetch_assoc", "Medium - SQLi (MySQL function)"),
    (r"ORA-\d{5}", "High - SQLi (Oracle error)"),
    (r"ORA-\d{4}", "Medium - SQLi (Oracle error)"),
    (r"PostgreSQL.*ERROR|PG::.*Error", "High - SQLi (PostgreSQL error)"),
    (r"Microsoft OLE DB.*SQL Server", "High - SQLi (MSSQL error)"),
    (r"Unclosed quotation mark", "High - SQLi (MSSQL unclosed quote)"),
    (r"Incorrect syntax near", "High - SQLi (MSSQL syntax error)"),
    (r"Division by zero.*SQL", "Medium - SQLi (SQL division error)"),
    (r"SQLite.*Error", "High - SQLi (SQLite error)"),
    (r"SQLite3::", "High - SQLi (SQLite3 exception)"),
    (r"not all arguments converted", "Medium - SQLi (Python DB error)"),
    (r"supplied argument is not a valid MySQL", "Medium - SQLi (PHP MySQL error)"),
    (r"Column count doesn't match", "High - SQLi (column mismatch)"),
    (r"Unknown column.*in 'field list'", "High - SQLi (unknown column)"),
    (r"Table.*doesn't exist", "High - SQLi (missing table)"),
    (r"Duplicate entry.*for key", "Medium - SQLi (duplicate entry)"),
    (r"Syntax error.*SQL", "Medium - SQLi (generic SQL syntax)"),
    (r"Warning.*mysql_", "Low - SQLi (PHP MySQL warning)"),

    # === SSTI ===
    (r"FreeMarker template error", "Critical - SSTI (FreeMarker)"),
    (r"TemplateError", "High - SSTI (Generic)"),
    (r"Template.*undefined", "High - SSTI (undefined variable)"),
    (r"Jinja2.*Error|jinja2.*undefined", "High - SSTI (Jinja2 error)"),
    (r"UndefinedError", "High - SSTI (Jinja2 undefined)"),
    (r"TemplateSyntaxError", "High - SSTI (syntax error)"),
    (r"is undefined", "Medium - SSTI (undefined variable)"),
    (r"TemplateNotFound", "Medium - SSTI (template not found)"),
    (r"49", "Low - SSTI (7*7=49 arithmetic)"),
    (r"__class__|__mro__|__subclasses__", "Critical - SSTI (sandbox escape)"),
    (r"self.*__globals__", "Critical - SSTI (globals access)"),
    (r"config.*SECRET_KEY", "High - SSTI (Flask config leak)"),
    (r"os\.popen|os\.system", "Critical - SSTI (OS command)"),
    (r"subprocess\.", "Critical - SSTI (subprocess access)"),

    # === XXE ===
    (r"root:x:0:0:", "Critical - XXE (/etc/passwd)"),
    (r"<!DOCTYPE.*SYSTEM", "High - XXE (DOCTYPE with SYSTEM)"),
    (r"<!DOCTYPE.*PUBLIC", "Medium - XXE (DOCTYPE with PUBLIC)"),
    (r"ENTITY.*SYSTEM", "High - XXE (entity with SYSTEM)"),
    (r"xinclude", "Medium - XXE (XInclude)"),
    (r"XML parsing error", "Medium - XXE (parse error)"),
    (r"SAXParseException", "Medium - XXE (SAX parse error)"),

    # === SSRF ===
    (r"aws-keys|aws_secret|AWS_ACCESS", "High - SSRF (cloud metadata)"),
    (r"169\.254\.169\.254", "Critical - SSRF (metadata IP)"),
    (r"instance-id|local-ipv4|public-keys", "High - SSRF (EC2 metadata)"),
    (r"iam/security-credentials", "Critical - SSRF (IAM role)"),
    (r"computeMetadata", "Medium - SSRF (GCP metadata)"),
    (r"TaskRoleArn|ECS_CONTAINER_METADATA", "High - SSRF (AWS ECS metadata)"),
    (r"KUBERNETES_SERVICE_HOST", "High - SSRF (K8s env)"),
    (r"kubernetes\.default", "Medium - SSRF (K8s service)"),

    # === XSS ===
    (r"<script>alert\(.*?\)</script>", "Medium - Reflected XSS (alert)"),
    (r"<script>prompt\(.*?\)</script>", "Medium - Reflected XSS (prompt)"),
    (r"<img\s+src.*?onerror=", "High - Reflected XSS (img onerror)"),
    (r"<svg/onload=", "High - Reflected XSS (svg onload)"),
    (r"<body\s+onload=", "High - Reflected XSS (body onload)"),
    (r"<input\s+onfocus=", "Medium - Reflected XSS (input onfocus)"),
    (r"javascript:\s*alert", "Medium - Reflected XSS (javascript URI)"),
    (r"onmouseover=", "Low - Reflected XSS (onmouseover)"),
    (r"<math><mtext><table><mglyph><style><!--</", "High - XSS (mathml mtext)"),
    (r"<details/open/ontoggle=", "High - XSS (details ontoggle)"),

    # === Open Redirect ===
    (r"window\.location\s*=\s*[\"']https?://", "Medium - Open Redirect (JS redirect)"),
    (r"top\.location\s*=\s*[\"']https?://", "Medium - Open Redirect (top redirect)"),
    (r"document\.location\s*=\s*[\"']https?://", "Medium - Open Redirect (doc redirect)"),
    (r"window\.open\([\"']https?://", "Medium - Open Redirect (window.open)"),
    (r"<meta\s+http-equiv=\"refresh\"", "Low - Open Redirect (meta refresh)"),

    # === Information Disclosure ===
    (r"Stack trace:|Traceback \(most recent call last\)", "High - Info Disclosure (stack trace)"),
    (r"DEBUG=True|DEBUG = True", "High - Info Disclosure (debug mode)"),
    (r"ALLOWED_HOSTS\s*=\s*\['\*'\]", "Medium - Info Disclosure (lax allowed hosts)"),
    (r"SECRET_KEY\s*=", "Critical - Info Disclosure (Django secret)"),
    (r"APP_SECRET|app_secret", "High - Info Disclosure (app secret)"),
    (r"internal IP|private IP|10\.\d+\.\d+\.\d+", "Low - Info Disclosure (internal IP)"),
    (r"Server:.*Apache/2\.4\.\d+", "Low - Version Disclosure (Apache)"),
    (r"Server:.*nginx/1\.\d+\.\d+", "Low - Version Disclosure (nginx)"),
    (r"X-Powered-By:.*PHP/8\.\d+", "Low - Version Disclosure (PHP)"),
    (r"X-AspNet-Version:", "Low - Version Disclosure (ASP.NET)"),
    (r"X-AspNetMvc-Version:", "Low - Version Disclosure (ASP.NET MVC)"),

    # === Command Injection ===
    (r"uid=\d+|gid=\d+", "High - CMDi (id output)"),
    (r"(www|root|nobody|daemon):x:\d+:\d+:", "Critical - CMDi (/etc/passwd)"),
    (r"\d+ packets? transmitted", "High - CMDi (ping output)"),
    (r"\d+ received, \d+% packet loss", "High - CMDi (ping statistics)"),
    (r"1?HOST\s+.*ADDRESS", "Medium - CMDi (nslookup)"),
    (r"Name:\s+\S+\s+Address:", "Medium - CMDi (nslookup)"),
    (r"whoami|who am i", "Medium - CMDi (whoami leak)"),
    (r"hostname|Hostname", "Medium - CMDi (hostname leak)"),

    # === NoSQL Injection ===
    (r"mongodb.*error|MongoDB.*Error", "High - NoSQLi (Mongo error)"),
    (r"Invalid BSON|BSONObj", "Medium - NoSQLi (BSON error)"),
    (r"mongodb\.connect", "Low - NoSQLi (Mongo connect)"),
    (r"MongoError|MongoCursorException", "High - NoSQLi (Mongo exception)"),

    # === GraphQL ===
    (r"\"errors\".*\"GraphQL\"", "High - GraphQL introspection"),
    (r"__schema|__type|__typename", "Medium - GraphQL introspection"),
    (r"query\s+IntrospectionQuery", "High - GraphQL introspection query"),
    (r"PossibleType|possibleTypes", "Medium - GraphQL possibleTypes"),

    # === WebSocket ===
    (r"websocket|web_socket|ws://|wss://", "Low - WebSocket endpoint"),
    (r"Sec-WebSocket-Accept:", "Low - WebSocket upgrade"),

    # === Server-Side Includes ===
    (r"<!--#echo\s+var=", "Medium - SSI (echo)"),
    (r"<!--#exec\s+cmd=", "Critical - SSI (exec)"),
    (r"<!--#include\s+virtual=", "Medium - SSI (include)"),
    (r"<!--#fsize\s+var=", "Low - SSI (fsize)"),
    (r"<!--#flastmod\s+var=", "Low - SSI (flastmod)"),

    # === .env / Config Files ===
    (r"APP_ENV|APP_DEBUG|APP_KEY", "High - Config leak (Laravel .env)"),
    (r"DB_CONNECTION|DB_DATABASE|DB_HOST", "High - Config leak (DB config)"),
    (r"MAIL_DRIVER|MAIL_HOST|MAIL_USERNAME", "Medium - Config leak (mail config)"),
    (r"REDIS_HOST|REDIS_PASSWORD", "Medium - Config leak (Redis config)"),
    (r"STRIPE_KEY|STRIPE_SECRET", "Critical - Config leak (Stripe)"),
    (r"S3_KEY|S3_SECRET|S3_BUCKET", "Critical - Config leak (S3)"),
    (r"JWT_SECRET|JWT_KEY", "Critical - Config leak (JWT secret)"),
    (r"HASHIDS_SALT|NONCE_SALT", "High - Config leak (hash salt)"),

    # === Cloud Metadata ===
    (r"computeMetadata.*google", "High - GCP metadata"),
    (r"169\.254\.169\.254.*metadata", "Critical - Cloud metadata"),
    (r"metadata\.google\.internal", "High - GCP internal metadata"),
    (r"instance/attributes/ssh-keys", "High - GCP SSH keys"),
    (r"project/project-id", "Medium - GCP project ID"),
    (r"dynamic/instance-identity", "Medium - AWS identity doc"),

    # === Java-Specific ===
    (r"javax\.servlet|ServletException", "Medium - Java servlet error"),
    (r"org\.apache\.tomcat", "Medium - Tomcat disclosure"),
    (r"org\.springframework", "Medium - Spring framework"),
    (r"java\.lang\.\w+Exception", "Medium - Java exception"),
    (r"JBoss|WildFly|Undertow", "Low - Java server header"),

    # === Python-Specific ===
    (r"wsgi\.errors\.py", "Medium - WSGI error page"),
    (r"Django.*Error|django\.", "Medium - Django error"),
    (r"Flask.*Error|flask\.", "Medium - Flask error"),
    (r"\.jinja|\.j2|\.jinja2", "Low - Jinja template"),
    (r"ModuleNotFoundError", "Medium - Python import error"),
    (r"AttributeError.*NoneType", "Low - Python null ref"),

    # === CORS / Security Misconfig ===
    (r"Access-Control-Allow-Origin: \*", "Medium - CORS wildcard"),
    (r"Access-Control-Allow-Credentials: true", "Medium - CORS with credentials"),
    (r"Access-Control-Allow-Methods:.*\*", "Low - CORS wildcard methods"),

    # === Cache & Proxy ===
    (r"X-Cache:.*HIT|X-Cache:.*MISS", "Low - Cache disclosure"),
    (r"X-Backend-Server:|X-Debug:", "Low - Backend disclosure"),
    (r"X-Varnish:|Via:", "Low - Proxy disclosure"),
]


class Detector:
    def __init__(self):
        self.signatures = SIGNATURES

    def scan(self, response_text: str) -> List[str]:
        matches = []
        for pattern, name in self.signatures:
            try:
                if re.search(pattern, response_text, re.IGNORECASE):
                    matches.append(name)
            except re.error:
                continue
        return matches

    def scan_headers(self, headers: dict) -> List[str]:
        findings = []
        for key, value in headers.items():
            key_lower = key.lower()
            if key_lower == "server" and value:
                findings.append(f"Low - Server banner: {value}")
            if key_lower == "x-powered-by" and value:
                findings.append(f"Low - Powered by: {value}")
            if key_lower == "x-aspnet-version":
                findings.append(f"Low - ASP.NET version: {value}")
            if key_lower == "via":
                findings.append(f"Low - Proxy: {value}")
        return findings

    def check_heuristics(self, baseline_text: str, response_text: str, payload: str) -> List[str]:
        heuristics = []
        if payload and len(payload) > 3:
            if payload in response_text:
                if payload not in baseline_text:
                    heuristics.append("Medium - Payload Reflected (Potential XSS/SSTI)")

        return heuristics

"""Security rules, taint sources, sinks, sanitizers, and CWE catalog."""

from typing import Dict, List, Set, Any
from ..models import VulnerabilityCategory, VulnerabilitySeverity


# Common untrusted input sources (API functions, attributes, and framework entry points)
TAINT_SOURCES = {
    # Generic standard library
    "input(", "sys.argv", "os.environ", "os.getenv",
    # Flask
    "request.args", "request.form", "request.values", "request.json",
    "request.get_json", "request.files", "request.headers", "request.cookies",
    "request.data",
    # Django
    "request.GET", "request.POST", "request.body", "request.META"
}

# Dangerous sinks mapped to vulnerability category
TAINT_SINKS = {
    # CWE-78: OS Command Injection
    "os.system": VulnerabilityCategory.COMMAND_INJECTION,
    "os.popen": VulnerabilityCategory.COMMAND_INJECTION,
    "subprocess.run": VulnerabilityCategory.COMMAND_INJECTION,
    "subprocess.Popen": VulnerabilityCategory.COMMAND_INJECTION,
    "subprocess.call": VulnerabilityCategory.COMMAND_INJECTION,
    "subprocess.check_output": VulnerabilityCategory.COMMAND_INJECTION,
    "subprocess.check_call": VulnerabilityCategory.COMMAND_INJECTION,
    
    # CWE-89: SQL Injection
    "cursor.execute": VulnerabilityCategory.SQL_INJECTION,
    "cursor.executemany": VulnerabilityCategory.SQL_INJECTION,
    "connection.execute": VulnerabilityCategory.SQL_INJECTION,
    "db.execute": VulnerabilityCategory.SQL_INJECTION,
    "session.execute": VulnerabilityCategory.SQL_INJECTION,
    
    # CWE-22: Path Traversal
    "open": VulnerabilityCategory.PATH_TRAVERSAL,
    "os.remove": VulnerabilityCategory.PATH_TRAVERSAL,
    "os.unlink": VulnerabilityCategory.PATH_TRAVERSAL,
    "os.listdir": VulnerabilityCategory.PATH_TRAVERSAL,
    "send_file": VulnerabilityCategory.PATH_TRAVERSAL,
    "shutil.copy": VulnerabilityCategory.PATH_TRAVERSAL,
    
    # CWE-502: Insecure Deserialization
    "pickle.loads": VulnerabilityCategory.INSECURE_DESERIALIZATION,
    "pickle.load": VulnerabilityCategory.INSECURE_DESERIALIZATION,
    "_pickle.loads": VulnerabilityCategory.INSECURE_DESERIALIZATION,
    "yaml.load": VulnerabilityCategory.INSECURE_DESERIALIZATION,
    
    # CWE-918: Server-Side Request Forgery (SSRF)
    "requests.get": VulnerabilityCategory.SSRF,
    "requests.post": VulnerabilityCategory.SSRF,
    "requests.request": VulnerabilityCategory.SSRF,
    "urllib.request.urlopen": VulnerabilityCategory.SSRF,
    "httpx.get": VulnerabilityCategory.SSRF,
    "httpx.post": VulnerabilityCategory.SSRF,
    
    # CWE-79: Cross-Site Scripting (XSS)
    "markupsafe.Markup": VulnerabilityCategory.XSS,
    "flask.render_template_string": VulnerabilityCategory.XSS,
    
    # CWE-327: Broken / Insecure Cryptography
    "hashlib.md5": VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
    "hashlib.sha1": VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
    "Crypto.Cipher.DES.new": VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
}

# Recognized sanitizers / validators by category
SANITIZERS: Dict[VulnerabilityCategory, Set[str]] = {
    VulnerabilityCategory.COMMAND_INJECTION: {
        "shlex.quote", "shlex.split", "shell=False"
    },
    VulnerabilityCategory.SQL_INJECTION: {
        "parameterized", "execute_params", "prepare", "int", "float"
    },
    VulnerabilityCategory.PATH_TRAVERSAL: {
        "os.path.abspath", "os.path.realpath", "Path.resolve", "os.path.basename",
        "secure_filename", "commonpath", "startswith"
    },
    VulnerabilityCategory.INSECURE_DESERIALIZATION: {
        "yaml.safe_load", "yaml.CSafeLoader", "json.loads"
    },
    VulnerabilityCategory.SSRF: {
        "validate_url", "allowed_hosts", "urlparse", "is_safe_url"
    },
    VulnerabilityCategory.WEAK_CRYPTOGRAPHY: {
        "hashlib.sha256", "hashlib.sha512", "bcrypt.hashpw", "argon2"
    }
}

# Detailed rule catalog metadata
RULE_CATALOG: Dict[str, Dict[str, Any]] = {
    "CWE-78": {
        "name": "OS Command Injection",
        "severity": VulnerabilitySeverity.CRITICAL,
        "description": "Constructing OS commands with untrusted user input without shell escaping allows arbitrary command execution.",
        "remediation": "Avoid invoking shell directly (`shell=False`), pass command arguments as a list, and sanitize variables using `shlex.quote()`."
    },
    "CWE-89": {
        "name": "SQL Injection",
        "severity": VulnerabilitySeverity.HIGH,
        "description": "Building SQL queries via dynamic string concatenation or f-strings with untrusted input exposes database to extraction and manipulation.",
        "remediation": "Use parameterized queries with placeholders (`?` or `%s`), prepared statements, or a vetted ORM."
    },
    "CWE-22": {
        "name": "Path Traversal",
        "severity": VulnerabilitySeverity.HIGH,
        "description": "Accessing files using unvalidated input containing path traversal sequences (`../`) allows unauthorized filesystem access.",
        "remediation": "Canonicalize target path using `os.path.abspath()` or `Path.resolve()` and verify it starts with the permitted base directory, or use `os.path.basename()`."
    },
    "CWE-502": {
        "name": "Insecure Deserialization",
        "severity": VulnerabilitySeverity.CRITICAL,
        "description": "Deserializing untrusted data with `pickle` or `yaml.load(Loader=Loader)` can lead to remote code execution.",
        "remediation": "Use safe data serialization formats like JSON (`json.loads`), or `yaml.safe_load()`. Avoid `pickle` on untrusted payloads."
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "severity": VulnerabilitySeverity.HIGH,
        "description": "Fetching remote resources from unvalidated user-supplied URLs can allow attackers to probe internal networks or cloud metadata endpoints.",
        "remediation": "Validate target URL schemes, restrict destinations to an allowlist of permitted hosts/IPs, and block private RFC1918 addresses and link-local metadata endpoints."
    },
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "severity": VulnerabilitySeverity.MEDIUM,
        "description": "Rendering untrusted input directly into HTML without escaping allows arbitrary script execution in client browsers.",
        "remediation": "Apply context-aware HTML escaping, use safe template engines with auto-escaping enabled, and avoid `Markup` on raw user input."
    },
    "CWE-798": {
        "name": "Hardcoded Credentials",
        "severity": VulnerabilitySeverity.HIGH,
        "description": "Hardcoded passwords, API tokens, or private keys in source code can be extracted and abused.",
        "remediation": "Store secrets in secure environment variables, secret managers (e.g. AWS Secrets Manager, HashiCorp Vault), or git-ignored configuration files."
    },
    "CWE-327": {
        "name": "Use of Broken or Risky Cryptographic Algorithm",
        "severity": VulnerabilitySeverity.MEDIUM,
        "description": "Using deprecated algorithms like MD5 or SHA-1 for passwords or integrity checks is vulnerable to collisions and pre-image attacks.",
        "remediation": "Upgrade to cryptographically strong hash functions (SHA-256/SHA-512) for integrity, or modern salted password algorithms (bcrypt, Argon2, PBKDF2)."
    },
    "CWE-1395": {
        "name": "Vulnerable Third-Party Dependency",
        "severity": VulnerabilitySeverity.HIGH,
        "description": "The application relies on a dependency version with known public vulnerability advisories (CVE/GHSA).",
        "remediation": "Upgrade the package in your dependency manifest (`requirements.txt`, `pyproject.toml`, or `package.json`) to a non-vulnerable fixed release."
    }
}

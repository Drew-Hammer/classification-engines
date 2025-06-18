#pragma once

#include <map>
#include <string>
#include <vector>

namespace security {

// Severity scores for each category (0.1 to 0.9)
const std::map<std::string, double> CATEGORY_SEVERITY = {
    {"Vulnerability", 0.9},
    {"Privilege Escalation", 0.85},
    {"Attack", 0.8},
    {"Authentication", 0.75},
    {"Identity & Access Management", 0.7},
    {"Access Control", 0.65},
    {"API Security", 0.6},
    {"Network Security", 0.55},
    {"Cloud Security", 0.5},
    {"Container Security", 0.45},
    {"Data Security", 0.4},
    {"Storage Security", 0.35},
    {"Infrastructure", 0.3},
    {"Defense", 0.3},
    {"Incident Response", 0.25},
    {"DevOps Security", 0.25},
    {"Orchestration Security", 0.2},
    {"Supply Chain", 0.2},
    {"Social Engineering", 0.15},
    {"Configuration Management", 0.15},
    {"Logging & Auditing", 0.1},
    {"Compliance", 0.1},
    {"Cryptography", 0.7},
    {"Mobile Security", 0.45},
    {"Web Security", 0.5},
    {"Physical Security", 0.2},
    {"Threat Intelligence", 0.35},
    {"SIEM", 0.3},
    {"Insider Threats", 0.4},
    {"Zero Trust", 0.35},
    {"Security Awareness", 0.2},
    {"Patch Management", 0.25},
    {"Red Teaming", 0.3},
    {"Blue Teaming", 0.3},
    {"Bug Bounty", 0.2},
    {"Security Architecture", 0.3},
    {"DDoS Protection", 0.3},
    {"Web Application Firewall", 0.25}
};

const std::map<std::string, std::vector<std::string>> CATEGORY_KEYWORDS = {
     {"Vulnerability", {
        "vulnerability", "weakness", "exposure", "flaw", "bug", "defect", "issue", "hole", "security hole",
        "misconfiguration", "configuration error", "exploit", "zero-day", "0day", "cve", "cwe", "vuln",
        "overflow", "underflow", "race condition", "buffer overflow", "memory corruption", "segfault",
        "null pointer", "dangling pointer", "type confusion", "unauthorized", "unsafe", "invalid state",
        "broken", "deserialization", "unvalidated", "unescaped", "unpatched", "bypass", "escalate",
        "insecure", "improper", "insufficient", "vulnerable", "injection flaw", "path traversal",
        "access violation", "improper check", "use after free"
    }},

    {"Attack", {
        "malware", "virus", "ransomware", "spyware", "trojan", "backdoor", "botnet", "worm",
        "exploit", "injection", "sql injection", "xss", "cross-site", "command injection", "payload",
        "phishing", "spoofing", "man-in-the-middle", "session hijack", "credential stuffing",
        "attack", "breach", "compromise", "intrusion", "infiltration", "malicious", "threat",
        "adversary", "hacker", "attacker", "shellcode", "rootkit", "reconnaissance", "escalation",
        "lateral movement", "exfiltration", "social engineering", "brute force", "spear phishing",
        "watering hole", "dns tunneling", "malicious script", "email attack"
    }},

    {"Incident Response", {
        "incident", "response", "alert", "alarm", "notification", "event", "event detection",
        "investigation", "forensics", "analysis", "triage", "containment", "contain", "remediate",
        "eradication", "recovery", "remediation", "report", "log", "monitoring", "detection",
        "tracking", "incident handler", "playbook", "ir", "escalation", "timeline",
        "root cause", "compromise assessment", "csirt", "sitrep", "postmortem", "outage",
        "blameless postmortem", "alert fatigue", "runbook"
    }},

    {"Authentication", {
        "authentication", "verify identity", "login", "login failure", "password reuse",
        "invalid credentials", "token theft", "otp failure", "2fa", "mfa", "authentication bypass",
        "unauthenticated", "spoofed login", "sign in", "auth failure", "auth error",
        "session hijack", "passwordless", "device auth", "password compromise",
        "authentication token", "oauth", "saml", "openid connect", "identity provider"
    }},

    {"Identity & Access Management", {
        "iam", "identity", "role", "policy", "access key", "identity federation", "trust relationship",
        "principal", "sts", "role assumption", "cross-account access", "least privilege",
        "access control list", "authorization", "privilege", "authentication", "user directory",
        "ldap", "sso", "oauth", "openid", "saml", "identity management", "directory service",
        "role-based access", "entitlement", "provisioning", "deprovisioning", "identity lifecycle"
    }},

    {"Access Control", {
        "password", "credential", "permission", "privilege", "access", "entitlement",
        "user", "admin", "role", "policy", "compliance", "authentication",
        "authorization", "identity", "account", "login", "session", "token",
        "certificate", "rights", "sudo", "root", "group", "lockout",
        "multi-factor", "mfa", "2fa", "otp", "biometrics", "authorization level",
        "delegation", "rbac", "abac", "iam", "ssh", "secure shell", "remote access",
        "key based auth", "public key auth", "private key", "key pair", "passphrase",
        "session timeout", "access revocation"
    }},

    {"API Security", {
        "api", "endpoint", "rest", "graphql", "openapi", "swagger", "api gateway", "rate limiting",
        "unauthorized access", "token leakage", "broken auth", "idor", "parameter tampering",
        "excessive data exposure", "injection", "rate limit bypass", "api key",
        "broken object level authorization", "endpoint enumeration", "api abuse",
        "client-side validation", "replay attack", "csrf token", "api fuzzing"
    }},

    {"Network Security", {
        "network", "firewall", "router", "switch", "packet", "traffic", "protocol", "port",
        "interface", "gateway", "dns", "ip", "tcp", "udp", "vpn", "proxy", "nat",
        "vlan", "segment", "perimeter", "intrusion", "egress", "ingress", "sniffer",
        "man-in-the-middle", "ssid", "spoofing", "arp", "dos", "ddos", "ssl", "tls",
        "open port", "ssh", "secure shell", "remote access", "encrypted connection",
        "secure connection", "network protocol", "remote shell", "tcpdump", "icmp",
        "packet drop", "packet loss", "latency", "qos"
    }},

    {"Cloud Security", {
        "cloud", "aws", "azure", "gcp", "iam", "cloud trail", "s3 bucket", "object storage",
        "cloud function", "lambda", "cloudwatch", "misconfigured bucket", "cloud identity",
        "cloud security", "secrets manager", "cloud credentials", "public bucket",
        "account compromise", "cloud-native", "instance metadata", "iam policy",
        "shared responsibility", "cloud api", "cloud config", "cloud perimeter",
        "cloud misconfig", "resource exposure"
    }},

    {"Container Security", {
        "container", "docker", "image", "registry", "container runtime", "container escape",
        "privileged container", "insecure image", "malicious image", "container vulnerability",
        "container isolation", "runC", "namespaces", "cgroups", "volume mount",
        "container exploit", "entrypoint abuse", "exposed docker", "overlay filesystem",
        "container daemon", "docker socket", "container orchestration", "container sprawl"
    }},

    {"Data Security", {
        "data", "information", "confidential", "sensitive", "private", "encrypted", "protected",
        "secure", "classified", "restricted", "secret", "proprietary", "confidentiality",
        "integrity", "availability", "backup", "storage", "database", "file", "dataset",
        "record", "pii", "phi", "data leak", "breach", "tokenization", "masking",
        "pseudonymization", "data loss", "exfiltration", "cloud storage", "s3",
        "data integrity", "data privacy", "data retention", "data at rest", "data in transit"
    }},

    {"Storage Security", {
        "storage", "object storage", "blob storage", "disk", "volume", "mount", "storage access",
        "encryption at rest", "storage leak", "shared volume", "storage exposure", "unsecured disk",
        "cloud storage", "efs", "nfs", "block device", "misconfigured share", "raid",
        "filesystem", "backup disk", "replication", "storage snapshot", "storage tier"
    }},

    {"Infrastructure", {
        "system", "server", "host", "endpoint", "workstation", "device", "computer", "hardware",
        "software", "application", "service", "platform", "infrastructure", "architecture",
        "cloud", "container", "virtual", "physical", "asset", "os", "kernel", "microservice",
        "hypervisor", "runtime", "orchestration", "kubernetes", "ci/cd", "availability zone",
        "data center", "fleet", "scaling", "deployment", "vm", "instance", "bare metal",
        "cluster", "node"
    }},

    {"Defense", {
        "firewall", "encryption", "authentication", "authorization", "patch", "update",
        "backup", "monitoring", "detection", "prevention", "protection", "safeguard",
        "defense", "mitigation", "countermeasure", "control", "security", "hardening",
        "remediation", "patching", "sandboxing", "zero trust", "rate limiting",
        "segmentation", "honeytoken", "resilience", "heuristics", "behavioral detection",
        "anomaly detection", "signature-based", "intrusion prevention", "active defense"
    }},
    
    {"DevOps Security", {
        "ci/cd", "ci cd", "ci pipeline", "devops", "dev ops", "dev-ops", "devops security",
        "build process", "build artifact", "code signing", "pipeline", "pipeline abuse",
        "source control", "github", "gitlab", "bitbucket", "repository", "commit",
        "secrets in repo", "cicd credential", "workflow abuse", "build server", "artifact injection",
        "script injection", "automation", "deployment pipeline", "insecure runner",
        "self-hosted runner", "pipeline token", "ci leak", "git secret"
    }},

    {"Orchestration Security", {
        "kubernetes", "k8s", "pod", "deployment", "cluster", "node", "service account",
        "role binding", "rbac", "etcd", "helm", "ingress", "network policy",
        "container orchestrator", "orchestration", "configmap", "secrets", "kubelet",
        "api server", "cluster-admin", "namespace isolation", "misconfigured cluster",
        "exposed dashboard", "cni plugin", "kubeconfig", "controller manager"
    }},

    {"Supply Chain", {
        "dependency", "supply chain", "third party", "vendor", "software supplier",
        "code injection", "package hijack", "dependency confusion", "typosquatting",
        "malicious library", "signed malware", "trust relationship", "open source risk",
        "sbom", "software bill of materials", "supplier compromise", "artifact integrity",
        "npm package", "pip package", "malicious commit", "cicd compromise"
    }},

    {"Social Engineering", {
        "phishing", "vishing", "smishing", "pretexting", "baiting", "impersonation",
        "social engineering", "manipulation", "deception", "fraud", "scam",
        "fake identity", "trust exploit", "coercion", "tailgating", "usb drop",
        "email fraud", "voice scam", "spoof call", "impersonation attack"
    }},

    {"Configuration Management", {
        "configuration", "misconfiguration", "default credentials", "open port",
        "exposed service", "unrestricted access", "public access", "security group",
        "firewall rule", "excessive permissions", "configuration drift", "settings",
        "parameter", "config file", "exposed config", "environment variable",
        "exposed secret", "insecure default", "cloud misconfig", "template flaw",
        "insecure config script"
    }},

    {"Logging & Auditing", {
        "log", "audit", "trail", "event", "record", "logging", "syslog", "debug",
        "trace", "audit trail", "tamper", "logfile", "observer", "timestamp",
        "change tracking", "accountability", "access log", "telemetry", "siem",
        "observability", "forensics", "log integrity", "log retention", "rotation",
        "event log", "audit policy", "log forwarding"
    }},

    {"Compliance", {
        "compliance", "regulation", "standard", "policy", "requirement", "audit",
        "assessment", "certification", "accreditation", "governance", "framework",
        "control", "guideline", "procedure", "baseline", "benchmark", "best-practice",
        "documentation", "sox", "gdpr", "hipaa", "pci", "nist", "iso", "fedramp",
        "cmmc", "cobit", "risk acceptance", "evidence", "reporting", "gap",
        "conformance", "compliance check", "compliance audit"
    }},

    {"Privilege Escalation", {
        "escalation", "privilege escalation", "root access", "admin rights", "elevation",
        "elevated", "unauthorized privilege", "gain access", "sudo abuse", "bypass privileges",
        "runas", "setuid", "token theft", "impersonation", "capability abuse",
        "permission elevation", "dll injection", "service misconfig", "cron job abuse"
    }},
    {"Cloud Security", {
        "cloud", "aws", "azure", "gcp", "iam", "cloud trail", "s3 bucket", "object storage",
        "cloud function", "lambda", "cloudwatch", "misconfigured bucket", "cloud identity",
        "cloud security", "secrets manager", "cloud credentials", "public bucket",
        "account compromise", "cloud-native", "instance metadata", "iam policy", "shared responsibility"
    }},

    {"Container Security", {
        "container", "docker", "image", "registry", "container runtime", "container escape",
        "privileged container", "insecure image", "malicious image", "container vulnerability",
        "container isolation", "runC", "namespaces", "cgroups", "volume mount",
        "container exploit", "entrypoint abuse", "exposed docker", "overlay filesystem"
    }},

    {"Orchestration Security", {
        "kubernetes", "k8s", "pod", "deployment", "cluster", "node", "service account",
        "role binding", "rbac", "etcd", "helm", "ingress", "network policy", "container orchestrator",
        "orchestration", "configmap", "secrets", "kubelet", "api server", "cluster-admin",
        "namespace isolation", "misconfigured cluster", "exposed dashboard", "cni plugin"
    }},

    {"API Security", {
        "api", "endpoint", "rest", "graphql", "openapi", "swagger", "api gateway", "rate limiting",
        "unauthorized access", "token leakage", "broken auth", "idor", "parameter tampering",
        "excessive data exposure", "injection", "rate limit bypass", "api key", "broken object level authorization"
    }},

    {"Storage Security", {
        "storage", "object storage", "blob storage", "disk", "volume", "mount", "storage access",
        "encryption at rest", "storage leak", "shared volume", "storage exposure", "unsecured disk",
        "cloud storage", "efs", "nfs", "block device", "misconfigured share"
    }},

    {"Identity & Access Management", {
        "iam", "identity", "role", "policy", "access key", "identity federation", "trust relationship",
        "principal", "sts", "role assumption", "cross-account access", "least privilege",
        "access control list", "authorization", "privilege", "authentication", "user directory",
        "ldap", "sso", "oauth", "openid", "saml"
    }},

    {"Configuration Management", {
        "configuration", "misconfiguration", "default credentials", "open port", "exposed service",
        "unrestricted access", "public access", "security group", "firewall rule", "excessive permissions",
        "configuration drift", "settings", "parameter", "config file", "exposed config", "environment variable",
        "exposed secret", "insecure default"
    }},

    {"DevOps Security", {
        "ci/cd", "ci cd", "ci pipeline", "devops", "dev ops", "dev-ops", "devops security"
        , "build process", "build artifact", "code signing", "pipeline", "pipeline abuse",
        "source control", "github", "gitlab", "bitbucket", "repository", "commit",
        "secrets in repo", "cicd credential", "workflow abuse", "build server", "artifact injection",
        "script injection", "automation", "deployment pipeline", "insecure runner"
    }},
     {"Cryptography", {
        "encryption", "decryption", "cipher", "aes", "rsa", "ecc", "key exchange",
        "symmetric", "asymmetric", "hash", "sha256", "md5", "digital signature",
        "key pair", "keystore", "certificate", "tls", "ssl", "secure channel",
        "encryption key", "public key", "private key", "key rotation", "hmac",
        "pbkdf2", "bcrypt", "scrypt", "padding oracle", "nonce", "iv", "cbc",
        "gcm", "encryption protocol", "crypto library", "ssl pinning"
    }},

    {"Mobile Security", {
        "mobile", "android", "ios", "apk", "ipa", "app security", "mobile app",
        "rooted", "jailbroken", "mobile malware", "sms spoofing", "app tampering",
        "app wrapping", "mobile device management", "mdm", "secure enclave",
        "biometric auth", "face id", "touch id", "insecure storage", "deeplink",
        "intent hijack", "mobile threat", "apktool", "frida", "obfuscation",
        "reverse engineering", "debuggable", "dynamic analysis", "static analysis"
    }},

    {"Web Security", {
        "web app", "csrf", "xss", "sql injection", "open redirect", "cookie theft",
        "session fixation", "content security policy", "csp", "cors", "reflected xss",
        "stored xss", "dom xss", "iframe injection", "clickjacking", "input validation",
        "output encoding", "secure headers", "path traversal", "lfi", "rfi",
        "ssrf", "subdomain takeover", "security.txt", "security misconfig",
        "robots.txt", ".env leak", "admin panel", "webshell", "htaccess",
        "parameter pollution", "broken session", "cookie flags"
    }},

    {"Physical Security", {
        "badge access", "keycard", "door lock", "cctv", "surveillance", "hardware theft",
        "tampering", "lock picking", "physical breach", "security guard", "access control",
        "biometric lock", "mantrap", "rfid", "asset tag", "inventory", "asset tracking",
        "server room", "environmental monitoring", "power backup", "camera feed"
    }},

    {"Threat Intelligence", {
        "ioc", "indicator of compromise", "tactics", "techniques", "procedures", "ttp",
        "apt", "threat actor", "campaign", "threat feed", "malware family", "threat report",
        "yara", "mitre", "att&ck", "cti", "cyber threat", "intel platform", "recon",
        "open source intel", "osint", "signature", "hash value", "ip address", "domain name"
    }},

    {"SIEM", {
        "siem", "log correlation", "alert rule", "dashboard", "kibana", "splunk",
        "elasticsearch", "indexing", "log ingestion", "security event", "alert tuning",
        "event normalization", "log forwarding", "log aggregator", "event management",
        "log retention", "dashboarding", "alert fatigue", "data enrichment", "log parsing"
    }},

    {"Insider Threats", {
        "insider", "employee misuse", "internal threat", "disgruntled employee",
        "data theft", "data leak", "intentional breach", "malicious insider",
        "access abuse", "unauthorized download", "file transfer", "email exfiltration",
        "usb drive", "shadow it", "privileged misuse", "credential sharing"
    }},

    {"Zero Trust", {
        "zero trust", "never trust", "always verify", "microsegmentation",
        "least privilege", "explicit verification", "assume breach",
        "identity centric", "continuous auth", "context aware access", "network isolation",
        "zero trust architecture", "zta", "zero trust model"
    }},

    {"Security Awareness", {
        "security training", "awareness campaign", "phishing training", "cyber hygiene",
        "best practices", "training exercise", "user awareness", "simulation",
        "security culture", "education", "security onboarding", "awareness material"
    }},

    {"Patch Management", {
        "patch", "update", "upgrade", "hotfix", "security patch", "version update",
        "patch cycle", "software update", "firmware update", "patch tuesday",
        "critical fix", "vulnerability patch", "change control", "release management"
    }},

    {"Red Teaming", {
        "red team", "penetration test", "ethical hacking", "exploit attempt",
        "red teaming exercise", "adversary emulation", "tactics techniques procedures",
        "physical intrusion", "social engineering test", "vulnerability assessment"
    }},

    {"Blue Teaming", {
        "blue team", "defensive strategy", "security monitoring", "incident detection",
        "response plan", "log review", "event triage", "network defense", "endpoint defense",
        "proactive defense", "incident preparedness"
    }},

    {"Bug Bounty", {
        "bug bounty", "vdp", "vulnerability disclosure", "researcher", "bugcrowd",
        "hackerone", "program policy", "responsible disclosure", "coordinated disclosure",
        "payout", "reward", "hall of fame", "submission", "scope restriction"
    }},

    {"Security Architecture", {
        "security architecture", "security design", "threat modeling", "secure by design",
        "architectural risk", "security pattern", "reference architecture", "layered security",
        "system modeling", "architecture flaw", "secure component"
    }},

    {"DDoS Protection", {
        "ddos", "dos", "rate limiting", "throttling", "load balancer", "cloudflare",
        "akamai", "traffic spike", "http flood", "amplification", "botnet", "reflected attack",
        "volumetric attack", "application-layer attack", "protection appliance"
    }},

    {"Web Application Firewall", {
        "waf", "web application firewall", "waf rule", "waf bypass", "modsecurity",
        "signature rule", "payload filtering", "web protection", "app layer filtering",
        "sql injection block", "xss filter", "http anomaly"
    }}
};

} // namespace security

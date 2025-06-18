#pragma once

#include <map>
#include <string>
#include <vector>

namespace security {

// Severity scores for each category (0.0 to 1.0)
const std::map<std::string, float> CATEGORY_SEVERITY = {
    {"Vulnerability", 0.9f},
    {"Attack", 0.85f},
    {"Incident Response", 0.8f},
    {"Authentication", 0.78f},
    {"Access Control", 0.75f},
    {"Network Security", 0.7f},
    {"Data Security", 0.7f},
    {"Defense", 0.65f},
    {"Social Engineering", 0.65f},
    {"Infrastructure", 0.6f},
    {"Supply Chain", 0.6f},
    {"Logging & Auditing", 0.55f},
    {"Compliance", 0.5f},
    {"Privilege Escalation", 0.88f},
    {"Cloud Security", 0.72f},
    {"Container Security", 0.7f},
    {"Orchestration Security", 0.68f},
    {"API Security", 0.74f},
    {"Storage Security", 0.66f},
    {"Identity & Access Management", 0.76f},
    {"Configuration Management", 0.58f},
    {"DevOps Security", 0.6f}
};

const std::map<std::string, std::vector<std::string>> CATEGORY_KEYWORDS = {
    {"Vulnerability", {
        "vulnerability", "weakness", "exposure", "flaw", "bug", "defect",
        "misconfiguration", "configuration error", "exploit", "zero-day", "cve", "risk",
        "overflow", "underflow", "race condition", "buffer overflow", "memory corruption",
        "null pointer", "dangling pointer", "type confusion", "unauthorized", "unsafe",
        "broken", "deserialization", "unvalidated", "unescaped", "unpatched", "bypass",
        "insecure", "improper", "insufficient", "vulnerable"
    }},

    {"Attack", {
        "malware", "virus", "ransomware", "spyware", "trojan", "backdoor",
        "exploit", "injection", "sql injection", "xss", "cross-site", "command injection",
        "phishing", "spoofing", "man-in-the-middle", "session hijack", "credential stuffing",
        "attack", "breach", "compromise", "intrusion", "infiltration", "malicious", "threat",
        "adversary", "hacker", "attacker", "payload", "shellcode", "rootkit", "reconnaissance",
        "escalation", "lateral movement", "exfiltration", "social engineering", "brute force"
    }},

    {"Incident Response", {
        "incident", "response", "alert", "alarm", "notification", "event",
        "investigation", "forensics", "analysis", "triage", "containment",
        "eradication", "recovery", "remediation", "report", "log",
        "monitoring", "detection", "tracking", "incident handler", "playbook",
        "ir", "escalation", "timeline", "root cause", "compromise assessment",
        "csirt", "sitrep", "postmortem", "outage"
    }},

    {"Authentication", {
        "authentication", "verify identity", "login", "login failure",
        "password reuse", "invalid credentials", "token theft", "otp failure",
        "2fa", "mfa", "authentication bypass", "unauthenticated", "spoofed login",
        "sign in", "auth failure", "auth error", "session hijack"
    }},

    {"Access Control", {
        "password", "credential", "permission", "privilege", "access",
        "user", "admin", "role", "policy", "compliance", "authentication",
        "authorization", "identity", "account", "login", "session",
        "token", "certificate", "rights", "sudo", "root", "group",
        "lockout", "multi-factor", "mfa", "2fa", "otp", "biometrics",
        "authorization level", "delegation", "rbac", "abac", "iam",
        "ssh", "secure shell", "remote access", "key based auth",
        "public key auth", "private key", "key pair", "passphrase"
    }},

    {"Network Security", {
        "network", "firewall", "router", "switch", "packet", "traffic",
        "protocol", "port", "interface", "gateway", "dns", "ip", "tcp",
        "udp", "vpn", "proxy", "nat", "vlan", "segment", "perimeter",
        "intrusion", "egress", "ingress", "sniffer", "man-in-the-middle",
        "ssid", "spoofing", "arp", "dos", "ddos", "ssl", "tls", "open port",
        "ssh", "secure shell", "remote access", "encrypted connection", 
        "secure connection", "network protocol", "remote shell"
    }},

    {"Data Security", {
        "data", "information", "confidential", "sensitive", "private",
        "encrypted", "protected", "secure", "classified", "restricted",
        "secret", "proprietary", "confidentiality", "integrity",
        "availability", "backup", "storage", "database", "file",
        "dataset", "record", "pii", "phi", "data leak", "breach",
        "tokenization", "masking", "pseudonymization", "data loss",
        "exfiltration", "cloud storage", "s3", "data integrity"
    }},

    {"Defense", {
        "firewall", "encryption", "authentication", "authorization", "patch",
        "update", "backup", "monitoring", "detection", "prevention", "protection",
        "safeguard", "defense", "mitigation", "countermeasure", "control",
        "security", "hardening", "remediation", "patching", "sandboxing",
        "zero trust", "rate limiting", "segmentation", "honeytoken", "resilience",
        "heuristics", "behavioral detection", "anomaly detection", "signature-based"
    }},

    {"Social Engineering", {
        "phishing", "vishing", "smishing", "pretexting", "baiting", "impersonation",
        "social engineering", "manipulation", "deception", "fraud", "scam",
        "fake identity", "trust exploit", "coercion", "tailgating", "usb drop"
    }},

    {"Infrastructure", {
        "system", "server", "host", "endpoint", "workstation", "device",
        "computer", "hardware", "software", "application", "service",
        "platform", "infrastructure", "architecture", "cloud", "container",
        "virtual", "physical", "asset", "os", "kernel", "microservice",
        "hypervisor", "runtime", "orchestration", "kubernetes", "ci/cd",
        "availability zone", "data center", "fleet", "scaling", "deployment"
    }},

    {"Supply Chain", {
        "dependency", "supply chain", "third party", "vendor", "software supplier",
        "code injection", "package hijack", "dependency confusion", "typosquatting",
        "malicious library", "signed malware", "trust relationship", "open source risk",
        "sbom", "software bill of materials", "supplier compromise", "artifact integrity"
    }},

    {"Logging & Auditing", {
        "log", "audit", "trail", "event", "record", "logging", "syslog", "debug",
        "trace", "audit trail", "tamper", "logfile", "observer", "timestamp",
        "change tracking", "accountability", "access log", "telemetry", "SIEM",
        "observability", "forensics", "log integrity", "log retention", "rotation"
    }},

    {"Compliance", {
        "compliance", "regulation", "standard", "policy", "requirement",
        "audit", "assessment", "certification", "accreditation", "governance",
        "framework", "control", "guideline", "procedure", "baseline",
        "benchmark", "best-practice", "documentation", "sox", "gdpr", "hipaa",
        "pci", "nist", "iso", "fedramp", "cmmc", "cobit", "risk acceptance",
        "evidence", "reporting", "gap", "conformance"
    }},

    {"Privilege Escalation", {
        "escalation", "privilege escalation", "root access", "admin rights",
        "elevation", "elevated", "unauthorized privilege", "gain access",
        "sudo abuse", "bypass privileges", "runas", "setuid", "token theft",
        "impersonation", "capability abuse", "permission elevation"
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
    }}
};

} // namespace security

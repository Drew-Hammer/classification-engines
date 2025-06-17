#pragma once

#include <map>
#include <string>
#include <vector>

namespace security {

// Severity scores for each category (0.0 to 1.0)
const std::map<std::string, float> CATEGORY_SEVERITY = {
    {"Vulnerability", 0.9f},          // Most severe - direct security weaknesses
    {"Attack", 0.85f},                // Active threats
    {"Incident Response", 0.8f},      // Critical response needed
    {"Authentication", 0.78f},        // Identity verification failures
    {"Access Control", 0.75f},        // Important security controls
    {"Network Security", 0.7f},       // Network-level protections
    {"Data Security", 0.7f},          // Data protection concerns
    {"Defense", 0.65f},               // General security measures
    {"Social Engineering", 0.65f},    // Human-centered attack vectors
    {"Infrastructure", 0.6f},         // System-level concerns
    {"Supply Chain", 0.6f},           // Vendor and third-party risk
    {"Logging & Auditing", 0.55f},    // Observability, logs, forensics
    {"Compliance", 0.5f},             // Policy and regulation
    {"Privilege Escalation", 0.88f}   // Unauthorized access level increase
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
        "authorization level", "delegation", "rbac", "abac", "iam"
    }},

    {"Network Security", {
        "network", "firewall", "router", "switch", "packet", "traffic",
        "protocol", "port", "interface", "gateway", "dns", "ip", "tcp",
        "udp", "vpn", "proxy", "nat", "vlan", "segment", "perimeter",
        "intrusion", "egress", "ingress", "sniffer", "man-in-the-middle",
        "ssid", "spoofing", "arp", "dos", "ddos", "ssl", "tls", "open port"
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
    }}
};

} // namespace security

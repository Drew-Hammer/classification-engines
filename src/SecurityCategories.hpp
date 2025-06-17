#pragma once

#include <map>
#include <string>
#include <vector>

namespace security {

// Severity scores for each category (0.0 to 1.0)
const std::map<std::string, float> CATEGORY_SEVERITY = {
    {"Vulnerability", 0.9f},      // Most severe - direct security weaknesses
    {"Attack", 0.85f},           // Active threats
    {"Incident Response", 0.8f},  // Critical response needed
    {"Access Control", 0.75f},    // Important security controls
    {"Network Security", 0.7f},   // Network-level protections
    {"Data Security", 0.7f},      // Data protection concerns
    {"Defense", 0.65f},          // General security measures
    {"Infrastructure", 0.6f},     // System-level concerns
    {"Compliance", 0.5f}         // Policy and regulation
};

const std::map<std::string, std::vector<std::string>> CATEGORY_KEYWORDS = {
    {"Vulnerability", {
        "vulnerability", "weakness", "exposure", "flaw", "bug", "defect",
        "misconfiguration", "exploit", "zero-day", "cve", "risk",
        "susceptibility", "vulnerable", "exposed", "unpatched"
    }},
    
    {"Attack", {
        "malware", "virus", "ransomware", "spyware", "trojan", "backdoor",
        "exploit", "injection", "phishing", "spoofing", "attack", "breach",
        "compromise", "intrusion", "infiltration", "malicious", "threat",
        "adversary", "hacker", "attacker", "payload", "shellcode"
    }},
    
    {"Defense", {
        "firewall", "encryption", "authentication", "authorization", "patch",
        "update", "backup", "monitoring", "detection", "prevention", "protection",
        "safeguard", "defense", "mitigation", "countermeasure", "control",
        "security", "hardening", "remediation", "patching"
    }},
    
    {"Access Control", {
        "password", "credential", "permission", "privilege", "access",
        "user", "admin", "role", "policy", "compliance", "authentication",
        "authorization", "identity", "account", "login", "session",
        "token", "certificate", "rights", "sudo", "root"
    }},
    
    {"Network Security", {
        "network", "firewall", "router", "switch", "packet", "traffic",
        "protocol", "port", "interface", "gateway", "dns", "ip", "tcp",
        "udp", "vpn", "proxy", "nat", "vlan", "segment", "perimeter"
    }},
    
    {"Data Security", {
        "data", "information", "confidential", "sensitive", "private",
        "encrypted", "protected", "secure", "classified", "restricted",
        "secret", "proprietary", "confidentiality", "integrity",
        "availability", "backup", "storage", "database", "file"
    }},
    
    {"Compliance", {
        "compliance", "regulation", "standard", "policy", "requirement",
        "audit", "assessment", "certification", "accreditation", "governance",
        "framework", "control", "guideline", "procedure", "baseline",
        "benchmark", "best-practice", "documentation"
    }},
    
    {"Incident Response", {
        "incident", "response", "alert", "alarm", "notification", "event",
        "investigation", "forensics", "analysis", "triage", "containment",
        "eradication", "recovery", "remediation", "report", "log",
        "monitoring", "detection", "tracking"
    }},
    
    {"Infrastructure", {
        "system", "server", "host", "endpoint", "workstation", "device",
        "computer", "hardware", "software", "application", "service",
        "platform", "infrastructure", "architecture", "cloud", "container",
        "virtual", "physical", "asset"
    }}
};

} // namespace security 
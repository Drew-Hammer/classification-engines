#pragma once

#include <map>
#include <string>
#include <vector>

namespace security {

// Severity scores for each category (0.1 to 0.9)
const std::map<std::string, double> CATEGORY_SEVERITY = {
    // CRITICAL (0.85-0.95) - Immediate system compromise or data breach risk
    {"Privilege Escalation", 0.95},  
    {"Access Control", 0.90},       
    {"Identity & Access Management", 0.90},  
    {"Data Security", 0.90},         
    {"Vulnerability", 0.85},         
    {"System Compromise", 0.85},    
    
    // HIGH (0.75-0.84) - Direct security threat
    {"Attack", 0.80},
    {"Authentication", 0.80},
    {"Cryptography", 0.80},
    {"Lateral Movement", 0.80},     
    
    // SIGNIFICANT (0.65-0.74) - Major security component
    {"API Security", 0.70},
    {"Container Security", 0.70},     
    {"Cloud Security", 0.70},
    {"Network Security", 0.70},       
    {"DevOps Security", 0.65},
    {"Defense Evasion", 0.70},      
    {"Service Availability", 0.65},  
    
    // MEDIUM (0.55-0.64) - Important security concerns
    {"Web Security", 0.61},          
    {"Zero Trust", 0.60},
    {"Storage Security", 0.55},
    {"Insider Threats", 0.55},
    
    // MODERATE (0.45-0.54) - Significant but not critical
    {"Threat Intelligence", 0.50},
    {"Infrastructure", 0.45},
    {"Orchestration Security", 0.45},
    
    // STANDARD (0.35-0.44) - Standard security measures
    {"Defense", 0.40},
    {"Incident Response", 0.40},
    {"Security Architecture", 0.40},
    {"DDoS Protection", 0.35},
    {"Web Application Firewall", 0.35},
    
    // BASELINE (0.25-0.34) - Important but lower risk
    {"Patch Management", 0.30},
    {"Configuration Management", 0.30},
    {"Physical Security", 0.25},
    
    // LOW (0.15-0.24) - Supporting security functions
    {"Logging & Auditing", 0.15},
    {"Compliance", 0.15}
};

const std::map<std::string, std::vector<std::string>> CATEGORY_KEYWORDS = {
    {"Data Security", {
        "data breach", "data exfiltration", "data leak", "data theft",
        "information disclosure", "sensitive data exposure", "data compromise",
        "unauthorized data access", "confidential data", "sensitive information", 
        "private data", "encrypted storage", "protected resource", "secure transmission",
        "classified information", "restricted access", "secret management", "proprietary information", 
        "data confidentiality", "data integrity", "data availability", "secure backup", 
        "database security", "dataset protection", "record security", "pii protection", 
        "phi security", "data leak", "security breach", "data tokenization", 
        "data masking", "data pseudonymization", "data loss", "data exfiltration", 
        "cloud storage security", "s3 security", "data integrity check", "data privacy control", 
        "data retention policy", "data at rest", "data in transit"
    }},

    {"Web Security", {
        "web application", "web app", "web vulnerability",
        "web app vulnerability", "application vulnerability",
        "csrf", "xss", "sql injection", "command injection",
        "code execution", "remote code execution", "command execution", "rce vulnerability",
        "open redirect protection", "cookie theft", "session hijacking",
        "session fixation", "content security policy", "csp", 
        "cors configuration", "reflected xss", "stored xss", 
        "dom xss", "iframe injection", "clickjacking", 
        "input validation", "output encoding", "secure headers", 
        "path traversal", "lfi", "rfi", 
        "ssrf", "subdomain takeover", "security.txt", 
        "misconfiguration", "robots.txt", ".env leak", 
        "admin panel", "webshell", "htaccess", 
        "parameter pollution", "session management", "cookie",
        "web server", "web server vulnerability", "web server compromise",
        "web application firewall", "waf bypass", "web cache poisoning",
        "web service", "web api", "web endpoint"
    }},

    {"Incident Response", {
        "security incident", "alert response", "incident detection",
        "forensic analysis", "incident triage", "threat containment", "system remediation",
        "threat eradication", "system recovery", "incident remediation", "security report", 
        "incident monitoring", "threat detection", "incident tracking", "incident handler", 
        "response playbook", "incident escalation", "incident timeline",
        "root cause analysis", "compromise assessment", "csirt team", "situation report", 
        "incident postmortem", "system outage", "blameless postmortem", "alert fatigue", 
        "response runbook"
    }},

    {"Authentication", {
        "multi-factor authentication", "identity verification", "login failure", "password reuse",
        "invalid credentials", "token theft", "otp failure", "2fa setup", "mfa bypass", 
        "authentication bypass", "unauthenticated access", "spoofed login", "auth failure", 
        "auth error", "session hijacking", "passwordless auth", "device authentication", 
        "password compromise", "authentication token", "oauth flow", "saml assertion", 
        "openid connect", "identity provider"
    }},

    {"Identity & Access Management", {
        "identity federation", "trust relationship", "role assumption", "cross-account access", 
        "least privilege access", "access control list", "user directory service",
        "single sign-on", "oauth implementation", "openid protocol", "saml configuration", 
        "identity management", "directory service", "role-based access", "user entitlement", 
        "user provisioning", "account deprovisioning", "identity lifecycle",
        "domain admin", "domain administrator", "domain controller",
        "privileged domain", "administrative domain", "admin privileges",
        "administrator privileges", "privileged access", "administrative access"
    }},

    {"Access Control", {
        "access permission", "privileged access", "user entitlement",
        "role-based policy", "compliance check", "multi-factor authentication",
        "identity verification", "account management", "session management", "token validation",
        "certificate management", "access rights", "sudo access", "root privilege", 
        "group permission", "account lockout", "multi-factor setup", "biometric verification", 
        "authorization level", "access delegation", "rbac implementation", "abac policy", 
        "ssh configuration", "secure shell setup", "remote access control",
        "key-based authentication", "public key infrastructure", "private key management", 
        "session timeout", "access revocation", "domain admin", "domain administrator",
        "domain controller", "privileged domain", "administrative domain", "admin privileges",
        "administrator privileges", "privileged access", "administrative access"
    }},

    {"API Security", {
        "api gateway", "rate limit", "unauthorized access", "token leakage", "broken authentication", 
        "object injection", "parameter tampering", "excessive data exposure", "api injection", 
        "rate limit bypass", "api key", "broken object authorization", 
        "endpoint enumeration", "api abuse", "client-side validation", 
        "replay attack", "csrf token validation", "api fuzzing"
    }},

    {"Network Security", {
        // Network Access Violations
        "ssh brute force attempt", "ftp credential stuffing",
        "smb null session exploit", "rdp authentication bypass",
        "telnet backdoor access", "vpn tunnel hijack",
        
        // Network Traffic Attacks
        "tcp syn flood", "udp amplification",
        "icmp smurf attack", "dns reflection",
        "arp cache poison", "mac address spoof",
        
        // Data Exfiltration Methods
        "dns tunneling", "https data smuggling",
        "icmp covert channel", "tcp reverse shell",
        "smtp data leak", "ftp binary transfer",
        
        // Active Reconnaissance
        "tcp port sweep", "udp service scan",
        "os fingerprint probe", "smb share enumeration",
        "snmp walk attempt", "dns zone transfer",
        
        // Protocol Exploitation
        "ssl heartbleed exploit", "smb eternal blue",
        "dns cache poison", "ldap injection",
        "smtp command inject", "http method tamper",
        
        // Infrastructure Breach
        "vlan hop attack", "router acl bypass",
        "firewall rule evade", "nat bypass attempt",
        "dmz boundary leap", "proxy chain break",
        
        // Service Disruption
        "http flood attack", "dns amplification",
        "tcp rst injection", "ssl renegotiation",
        "bgp route hijack", "dhcp starvation"
    }},

    {"Network Traffic Analysis", {
        // Traffic Capture and Monitoring
        "network traffic captured", "packet capture recorded",
        "network flow logged", "traffic analysis performed",
        "packet inspection performed", "deep packet inspection result",
        
        // Traffic Patterns
        "traffic pattern identified", "traffic baseline deviation",
        "traffic anomaly detected", "traffic signature matched",
        "traffic correlation found", "traffic behavior change",
        
        // Protocol Analysis
        "protocol violation found", "protocol anomaly detected",
        "protocol mismatch identified", "protocol abuse pattern",
        "protocol manipulation found", "protocol exploit attempt",
        
        // Network Flow Analysis
        "suspicious flow pattern", "abnormal flow volume",
        "unusual flow direction", "flow correlation detected",
        "flow timing anomaly", "flow size anomaly",
        
        // Packet Analysis
        "malformed packet found", "packet header anomaly",
        "packet payload anomaly", "packet sequence anomaly",
        "packet timing anomaly", "packet size anomaly",
        
        // Traffic Classification
        "malicious traffic identified", "command and control traffic",
        "data exfiltration traffic", "tunneled traffic detected",
        "encrypted traffic anomaly", "covert channel traffic"
    }},

    {"Cloud Security", {
        "aws", "azure", "gcp", "iam policy", "cloud trail", 
        "s3 bucket exposure", "object storage", "cloud function", 
        "lambda", "cloudwatch", "misconfigured bucket", 
        "cloud identity", "secrets manager", "cloud credentials", 
        "public bucket", "account compromise", "cloud-native", 
        "instance metadata", "shared responsibility", "cloud api", 
        "cloud config", "cloud perimeter", "cloud misconfiguration"
    }},

    {"Container Security", {
        "docker", "container image", "registry access", "container runtime", 
        "container escape", "privileged container", "insecure image",
        "malicious image", "container vulnerability", "container isolation",
        "runC vulnerability", "namespace", "cgroups", "volume mount",
        "container exploit", "entrypoint abuse", "exposed docker daemon", 
        "overlay filesystem"
    }},

    {"Storage Security", {
        "object storage", "blob storage", "disk encryption", 
        "volume", "mount", "storage access",
        "encryption at rest", "storage leak", "shared volume", 
        "storage exposure", "unsecured disk", "cloud storage", 
        "efs", "nfs", "block device encryption", "misconfigured share", 
        "raid"
    }},

    {"Infrastructure", {
        "system", "server", "host", "endpoint", 
        "workstation", "device", "hardware", "software",
        "application", "service", "platform", "cloud",
        "container", "virtual environment", "physical", "asset", 
        "kernel", "microservice", "hypervisor", "runtime",
        "kubernetes", "ci/cd pipeline", "availability zone", "data center",
        "fleet", "scaling", "deployment", "vm", 
        "bare metal", "cluster", "node"
    }},

    {"Defense", {
        "firewall", "encryption", "authentication", 
        "authorization", "patch", "update", "backup", 
        "monitoring", "threat detection", "intrusion", "protection", 
        "control", "hardening", "remediation", "patch", 
        "sandbox", "zero trust", "rate limit", "throttling",
        "load balancer", "cloudflare", "akamai", "traffic spike", "http flood",
        "amplification", "botnet", "reflected attack", "volumetric attack", "application-layer",
        "ddos appliance"
    }},
    
    {"DevOps Security", {
        "ci/cd", "pipeline", "build process", "code signing",
        "pipeline abuse", "source control", "github", "gitlab",
        "bitbucket", "repository", "commit signing", "secrets scanning",
        "cicd credential", "workflow", "build server", 
        "artifact injection", "script injection", "automation",
        "deployment pipeline", "runner", "self-hosted runner",
        "pipeline token", "ci leak", "git secret",
        "devops", "pipeline", "cicd", "jenkins", "gitlab", "github", "bitbucket",
        "repository", "build", "deploy", "automation", "artifact", "workflow",
        "continuous", "integration", "delivery", "deployment",
        "issue", "risk", "vulnerability", "breach",
        "incident", "concern", "problem"
    }},

    {"Orchestration Security", {
        "kubernetes", "k8s", "pod", "deployment", 
        "cluster", "node", "service account",
        "role binding", "rbac", "etcd", "helm", 
        "ingress", "network policy", "container orchestration",
        "configmap", "secrets", "kubelet", "api server",
        "cluster-admin", "namespace isolation", "misconfigured cluster",
        "dashboard", "cni plugin", "kubeconfig"
    }},

    {"Configuration Management", {
        "configuration hardening", "misconfiguration detection", "default credential management", 
        "port security", "service exposure", "access restriction", "public access control", 
        "security group management", "firewall rule configuration", "permission management", 
        "configuration drift detection", "settings management", "parameter validation", 
        "config file security", "exposed config detection", "environment variable protection",
        "exposed secret detection", "insecure default prevention", "cloud misconfiguration", 
        "template security", "insecure config detection"
    }},

    {"Logging & Auditing", {
        "log management", "audit trail", "event monitoring", "record keeping", "logging system", 
        "syslog configuration", "debug logging", "trace analysis", "audit verification", 
        "tamper detection", "logfile security", "observer pattern", "timestamp validation",
        "change tracking", "accountability system", "access logging", "telemetry collection", 
        "siem integration", "observability platform", "forensic analysis", "log integrity", 
        "log retention", "log rotation", "event logging", "audit policy", "log forwarding",
        "logging failure", "logging error", "logging issue", "audit failure", "audit issue",
        "packet capture", "packet monitoring", "packet sniffing", "traffic capture",
        "port scan", "port scanning", "scan port", "network scan"
    }},

    {"Privilege Escalation", {
        "privilege escalation detection", "root access control", "admin rights management", 
        "privilege elevation", "unauthorized privilege access", "access control bypass", 
        "sudo abuse", "privilege bypass", "runas restriction",
        "setuid control", "token theft", "user impersonation", "capability abuse",
        "permission elevation", "dll injection", "service misconfiguration",
        "cron job abuse", "domain admin", "domain administrator", "domain controller",
        "privileged domain", "administrative domain", "admin privileges"
    }},

    {"Cryptography", {
        "encryption protocol", "decryption process", "cipher", "aes encryption",
        "rsa algorithm", "ecc", "key exchange protocol", "symmetric encryption",
        "asymmetric encryption", "hash function", "sha256", "digital signature",
        "key pair management", "keystore security", "certificate management", "tls protocol",
        "ssl configuration", "secure channel setup", "encryption key management", 
        "public key infrastructure", "private key protection", "key rotation policy", 
        "hmac validation", "pbkdf2", "bcrypt usage", "scrypt",
        "padding oracle", "nonce generation", "iv management", "cbc mode",
        "gcm", "crypto library security", "ssl pinning"
    }},

    {"Physical Security", {
        "badge access control", "keycard management", "door lock system", "cctv monitoring",
        "surveillance system", "hardware theft prevention", "tamper detection", 
        "lock picking prevention", "physical breach detection", "security guard protocol",
        "access control system", "biometric lock system", "mantrap implementation", 
        "rfid security", "asset tag management", "inventory control", "asset tracking",
        "server room security", "environmental monitoring", "power backup system",
        "camera feed security"
    }},

    {"Threat Intelligence", {
        "ioc detection", "indicator of compromise", "threat tactics", "threat techniques",
        "threat procedures", "ttp analysis", "apt detection", "threat actor tracking",
        "campaign analysis", "threat feed integration", "malware family analysis", 
        "threat report generation", "yara rules", "mitre framework", "att&ck mapping",
        "cti platform", "cyber threat analysis", "intel platform integration", 
        "threat reconnaissance", "open source intelligence", "osint gathering",
        "threat signature", "hash verification", "ip reputation", "domain reputation"
    }},

    {"Insider Threats", {
        "insider threat", "employee monitoring", "internal threat",
        "employee risk", "data theft", "data leak",
        "intentional breach", "malicious insider",
        "access abuse monitoring", "unauthorized transfer", "file transfer monitoring",
        "email exfiltration", "usb security", "shadow it",
        "privileged account misuse", "credential sharing"
    }},

    {"Zero Trust", {
        "zero trust architecture", "trust verification", "microsegmentation",
        "least privilege", "explicit verification", "breach assumption",
        "identity-centric security", "continuous authentication", "context-aware access",
        "network isolation", "zero trust", "zta deployment",
        "zero trust model"
    }},

    {"Patch Management", {
        "patch deployment", "system update", "system upgrade", "hotfix",
        "security patch", "version control", "patch cycle",
        "software update", "firmware update", "patch tuesday",
        "critical fix", "vulnerability patching", "change control",
        "release management"
    }},

    {"Security Architecture", {
        "architecture design", "design pattern", "threat modeling",
        "design", "architectural risk", "pattern",
        "reference architecture", "layered", "system modeling",
        "architecture flaw", "component design"
    }},

    {"DDoS Protection", {
        "ddos mitigation", "dos prevention", "rate limit", "traffic throttling", "load balancer",
        "cloudflare protection", "akamai security", "traffic spike", "http flood",
        "amplification", "botnet", "reflected attack", "volumetric attack", "application-layer",
        "ddos appliance"
    }},

    {"Web Application Firewall", {
        "waf", "waf rule", "waf bypass",
        "modsecurity", "signature rule", "payload filtering",
        "web protection", "application filtering", "sql injection blocking",
        "xss filtering", "http anomaly"
    }},

    {"System Compromise", {
        // Privilege escalation patterns
        "privilege escalation to root", "privilege escalation to administrator", 
        "unauthorized root privilege obtained", "unauthorized admin privilege obtained",
        "elevated privileges via kernel exploit", "privilege elevation via buffer overflow",
        "remote code execution achieved", "arbitrary code execution obtained",
        "remote command shell established", "reverse shell connection established",
        "persistent backdoor installed", "covert command channel established",
        "unauthorized remote access via exploit", "malicious payload execution achieved",
        "kernel module compromise detected", "rootkit installation detected",
        "system binary modification detected", "critical system file tampering",
        "malicious kernel driver loaded", "system process injection detected",
        "memory resident rootkit detected", "bootkit installation detected",
        "firmware level compromise", "UEFI/BIOS compromise detected",
        "hypervisor level compromise", "container escape achieved",
        "sandbox escape detected", "VM escape achieved",
        "lateral movement via compromised host", "privilege persistence established",
        "system level persistence achieved", "startup process compromised",
        "system recovery mechanism disabled", "security mechanism disabled"
    }},

    {"Defense Evasion", {
        "monitoring bypass", "detection evasion", "security control bypass",
        "defense circumvention", "security evasion", "monitoring evasion",
        "stealth technique", "hidden access", "covert channel", "evasion technique",
        "security tool bypass", "antivirus evasion", "ids evasion", "ips bypass",
        "logging evasion", "audit evasion", "forensics evasion", "trace removal",
        "evidence cleanup", "activity masking", "defense layer bypass",
        "security product disable", "monitoring disable", "defense mechanism disable",
        "security tool tampering", "defense system compromise", "security agent disable",
        "detection system bypass", "security sensor blind", "defense layer penetration",
        "security control disable", "monitoring system bypass", "security monitoring blind"
    }},

    {"Service Availability", {
        // Core service states
        "service status", "service state", "service availability", "service disruption",
        "service outage", "service downtime", "service interruption", "service degradation",
        "service offline", "service disabled", "service stopped", "service failure",
        
        // Specific service types
        "web service status", "database service", "file service", "smb service",
        "network service", "dns service", "email service", "authentication service",
        "api service", "proxy service", "cache service", "queue service",
        
        // Port and protocol states
        "port status", "port availability", "port state", "port access",
        "protocol availability", "protocol state", "protocol access",
        "tcp port", "udp port", "service port", "listening port",
        
        // Impact descriptions
        "service impact", "service affected", "service compromised",
        "service unreachable", "service inaccessible", "service unstable",
        "service performance", "service response", "service latency",
        
        // Administrative actions
        "service shutdown", "service restart", "service suspension",
        "service maintenance", "service configuration", "service settings",
        "service modification", "service control", "service management",
        
        // Availability metrics
        "uptime impact", "availability loss", "service level",
        "performance degradation", "response time", "throughput reduction",
        "capacity impact", "bandwidth impact", "resource availability"
    }}
};

} // namespace security

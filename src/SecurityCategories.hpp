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
    {"Web Security", 0.85},          
    
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
    {"Zero Trust", 0.60},
    {"Storage Security", 0.55},
    {"Insider Threats", 0.55},
    
    // MODERATE (0.45-0.54) - Significant but not critical
    {"Mobile Security", 0.50},
    {"Supply Chain", 0.50},
    {"Threat Intelligence", 0.50},
    {"Infrastructure", 0.45},
    {"Orchestration Security", 0.45},
    
    // STANDARD (0.35-0.44) - Standard security measures
    {"Defense", 0.40},
    {"SIEM", 0.40},
    {"Incident Response", 0.40},
    {"Security Architecture", 0.40},
    {"DDoS Protection", 0.35},
    {"Web Application Firewall", 0.35},
    
    // BASELINE (0.25-0.34) - Important but lower risk
    {"Red Teaming", 0.30},
    {"Blue Teaming", 0.30},
    {"Patch Management", 0.30},
    {"Configuration Management", 0.30},
    {"Physical Security", 0.25},
    
    // LOW (0.15-0.24) - Supporting security functions
    {"Bug Bounty", 0.20},
    {"Social Engineering", 0.20},
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
        "phi security", "data leak prevention", "security breach", "data tokenization", 
        "data masking", "data pseudonymization", "data loss prevention", "data exfiltration", 
        "cloud storage security", "s3 security", "data integrity check", "data privacy control", 
        "data retention policy", "data at rest", "data in transit"
    }},

    {"Web Security", {
        "web application security", "web app security", "web security", "application security",
        "web vulnerability", "web app vulnerability", "application vulnerability",
        "csrf prevention", "xss protection", "sql injection", "command injection",
        "code execution", "remote code execution", "command execution", "rce vulnerability",
        "open redirect protection", "cookie theft prevention", "session hijacking",
        "session fixation", "content security policy", "csp implementation", 
        "cors configuration", "reflected xss prevention", "stored xss detection", 
        "dom xss protection", "iframe injection prevention", "clickjacking protection", 
        "input validation", "output encoding", "secure headers implementation", 
        "path traversal prevention", "lfi protection", "rfi detection", 
        "ssrf prevention", "subdomain takeover prevention", "security.txt implementation", 
        "security misconfiguration", "robots.txt security", ".env leak prevention", 
        "admin panel security", "webshell detection", "htaccess security", 
        "parameter pollution prevention", "session management", "cookie security",
        "web server security", "web server vulnerability", "web server compromise",
        "web application firewall", "waf bypass", "web cache poisoning",
        "web service security", "web api security", "web endpoint security"
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
        "api gateway", "rate limiting", "unauthorized access", "token leakage", "broken authentication", 
        "object injection", "parameter tampering", "excessive data exposure", "api injection", 
        "rate limit bypass", "api key management", "broken object authorization", 
        "endpoint enumeration", "api abuse prevention", "client-side validation", 
        "replay attack prevention", "csrf token validation", "api fuzzing test"
    }},

    {"Network Security", {
        "firewall configuration", "router setup", "network switch", 
        "traffic analysis", "protocol violation", "interface monitoring",
        "gateway security", "dns security", "vpn tunnel", "proxy server", "nat configuration",
        "vlan segmentation", "network perimeter", "intrusion detection", "traffic egress", 
        "traffic ingress", "man-in-the-middle attack", "wireless ssid", 
        "address spoofing", "denial of service", "distributed dos", "ssl certificate", 
        "tls protocol", "port exposure", "encrypted tunnel", "secure remote access", 
        "encrypted connection", "secure channel", "network monitoring", "remote shell security", 
        "icmp flood", "packet filtering", "network latency", "qos policy",
        "network pivot", "lateral movement", "network traversal", "network penetration",
        "internal network access", "network zone breach", "network segment compromise",
        "cross-network movement", "network access escalation", "unauthorized network movement",
        "network bridge compromise", "dmz breach", "internal zone access", "network hop",
        "network jump point", "pivot point compromise"
    }},

    {"Cloud Security", {
        "aws configuration", "azure setup", "gcp security", "iam policy", "cloud trail audit", 
        "s3 bucket exposure", "object storage security", "cloud function security", 
        "lambda configuration", "cloudwatch monitoring", "misconfigured bucket", 
        "cloud identity management", "secrets manager setup", "cloud credentials exposure", 
        "public bucket access", "account compromise detection", "cloud-native security", 
        "instance metadata service", "shared responsibility model", "cloud api security", 
        "cloud config management", "cloud perimeter security", "cloud misconfiguration"
    }},

    {"Container Security", {
        "docker security", "container image", "registry access", "container runtime", 
        "container escape prevention", "privileged container access", "insecure image detection", 
        "malicious image scan", "container vulnerability scan", "container isolation", 
        "runC vulnerability", "namespace security", "cgroups configuration", "volume mount security",
        "container exploit prevention", "entrypoint abuse prevention", "exposed docker daemon", 
        "overlay filesystem security"
    }},

    {"Storage Security", {
        "object storage protection", "blob storage security", "disk encryption", 
        "volume security", "mount protection", "storage access control",
        "encryption at rest", "storage leak prevention", "shared volume security", 
        "storage exposure prevention", "unsecured disk detection", "cloud storage security", 
        "efs protection", "nfs security", "block device encryption", "misconfigured share detection", 
        "raid configuration"
    }},

    {"Infrastructure", {
        "system hardening", "server security", "host protection", "endpoint security", 
        "workstation hardening", "device protection", "hardware security", "software protection",
        "application security", "service hardening", "platform security", "cloud infrastructure",
        "container security", "virtual environment", "physical security", "asset management", 
        "kernel hardening", "microservice security", "hypervisor protection", "runtime security",
        "kubernetes security", "ci/cd pipeline", "availability zone", "data center security",
        "fleet management", "scaling configuration", "deployment security", "vm protection", 
        "bare metal security", "cluster security", "node protection"
    }},

    {"Defense", {
        "firewall implementation", "encryption system", "authentication mechanism", 
        "authorization system", "patch management", "security update", "backup system", 
        "security monitoring", "threat detection", "intrusion prevention", "system protection", 
        "security control", "system hardening", "security remediation", "patch deployment", 
        "sandbox environment", "zero trust architecture", "rate limiting implementation",
        "network segmentation", "honeytoken deployment", "system resilience", 
        "heuristic analysis", "behavioral detection", "anomaly detection", 
        "signature-based detection", "intrusion prevention system", "active defense mechanism"
    }},
    
    {"DevOps Security", {
        "ci/cd security", "pipeline security", "build process security", "code signing process",
        "pipeline abuse prevention", "source control security", "github security", "gitlab protection",
        "bitbucket security", "repository hardening", "commit signing", "secrets scanning",
        "cicd credential management", "workflow security", "build server protection", 
        "artifact injection prevention", "script injection prevention", "automation security",
        "deployment pipeline security", "runner security", "self-hosted runner protection",
        "pipeline token management", "ci leak prevention", "git secret scanning",
        "devops", "pipeline", "cicd", "jenkins", "gitlab", "github", "bitbucket",
        "repository", "build", "deploy", "automation", "artifact", "workflow",
        "continuous", "integration", "delivery", "deployment",
        "security issue", "security risk", "security vulnerability", "security breach",
        "security incident", "security concern", "security problem"
    }},

    {"Orchestration Security", {
        "kubernetes security", "k8s hardening", "pod security", "deployment protection", 
        "cluster security", "node protection", "service account management",
        "role binding configuration", "rbac implementation", "etcd security", "helm security", 
        "ingress protection", "network policy enforcement", "container orchestration security",
        "configmap protection", "secrets management", "kubelet security", "api server protection",
        "cluster-admin restriction", "namespace isolation", "misconfigured cluster detection",
        "dashboard security", "cni plugin security", "kubeconfig management"
    }},

    {"Supply Chain", {
        "dependency scanning", "supply chain security", "third party assessment", 
        "vendor security", "software supplier verification", "code injection prevention", 
        "package hijacking prevention", "dependency confusion prevention", "typosquatting protection",
        "malicious library detection", "signed malware detection", "trust relationship verification", 
        "open source risk assessment", "sbom management", "software bill of materials", 
        "supplier compromise detection", "artifact integrity verification",
        "npm package security", "pip package verification", "malicious commit detection", 
        "cicd compromise prevention"
    }},

    {"Social Engineering", {
        "phishing prevention", "vishing detection", "smishing protection", "pretexting awareness",
        "baiting prevention", "impersonation detection", "social engineering awareness", 
        "manipulation prevention", "deception detection", "fraud prevention",
        "scam awareness", "fake identity detection", "trust exploitation", "coercion prevention",
        "tailgating prevention", "usb drop awareness", "email fraud detection", 
        "voice scam prevention", "spoof call detection", "impersonation prevention"
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

    {"Compliance", {
        "compliance monitoring", "regulation adherence", "standard implementation", 
        "policy enforcement", "requirement validation", "audit preparation",
        "assessment process", "certification process", "accreditation management", 
        "governance framework", "control implementation", "guideline enforcement", 
        "procedure documentation", "baseline configuration", "benchmark assessment", 
        "best-practice implementation", "documentation management", "sox compliance", 
        "gdpr compliance", "hipaa compliance", "pci compliance", "nist framework", 
        "iso certification", "fedramp authorization", "cmmc certification", "cobit framework",
        "risk acceptance", "evidence collection", "compliance reporting", "gap analysis",
        "conformance check", "compliance verification", "compliance audit"
    }},

    {"Privilege Escalation", {
        "privilege escalation detection", "root access control", "admin rights management", 
        "privilege elevation", "unauthorized privilege access", "access control bypass", 
        "sudo abuse prevention", "privilege bypass detection", "runas restriction",
        "setuid control", "token theft prevention", "user impersonation", "capability abuse",
        "permission elevation detection", "dll injection prevention", "service misconfiguration",
        "cron job abuse prevention", "domain admin", "domain administrator", "domain controller",
        "privileged domain", "administrative domain", "admin privileges"
    }},

    {"Cryptography", {
        "encryption protocol", "decryption process", "cipher implementation", "aes encryption",
        "rsa algorithm", "ecc implementation", "key exchange protocol", "symmetric encryption",
        "asymmetric encryption", "hash function", "sha256 implementation", "digital signature",
        "key pair management", "keystore security", "certificate management", "tls protocol",
        "ssl configuration", "secure channel setup", "encryption key management", 
        "public key infrastructure", "private key protection", "key rotation policy", 
        "hmac validation", "pbkdf2 implementation", "bcrypt usage", "scrypt configuration",
        "padding oracle prevention", "nonce generation", "iv management", "cbc mode",
        "gcm implementation", "crypto library security", "ssl pinning implementation"
    }},

    {"Mobile Security", {
        "mobile app security", "android protection", "ios security", "apk analysis", 
        "ipa verification", "app security assessment", "mobile app hardening",
        "root detection", "jailbreak detection", "mobile malware prevention", 
        "sms spoofing prevention", "app tampering detection", "app wrapping implementation",
        "mobile device management", "mdm configuration", "secure enclave implementation",
        "biometric authentication", "face id security", "touch id verification", 
        "insecure storage detection", "deeplink protection", "intent hijacking prevention",
        "mobile threat detection", "apktool analysis", "frida detection", "code obfuscation",
        "reverse engineering prevention", "debug protection", "dynamic analysis prevention",
        "static analysis detection"
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

    {"SIEM", {
        "log correlation", "alert rule configuration", "dashboard management", 
        "kibana implementation", "splunk deployment", "elasticsearch configuration",
        "log indexing", "log ingestion", "security event monitoring", "alert tuning",
        "event normalization", "log forwarding setup", "log aggregation", 
        "event management system", "log retention policy", "dashboard configuration",
        "alert fatigue management", "data enrichment", "log parsing rules"
    }},

    {"Insider Threats", {
        "insider threat detection", "employee monitoring", "internal threat prevention",
        "employee risk assessment", "data theft prevention", "data leak detection",
        "intentional breach prevention", "malicious insider detection",
        "access abuse monitoring", "unauthorized transfer detection", "file transfer monitoring",
        "email exfiltration prevention", "usb security", "shadow it detection",
        "privileged account misuse", "credential sharing prevention"
    }},

    {"Zero Trust", {
        "zero trust architecture", "trust verification", "microsegmentation implementation",
        "least privilege enforcement", "explicit verification", "breach assumption",
        "identity-centric security", "continuous authentication", "context-aware access",
        "network isolation", "zero trust implementation", "zta deployment",
        "zero trust model implementation"
    }},

    {"Patch Management", {
        "patch deployment", "system update", "system upgrade", "hotfix implementation",
        "security patch management", "version control", "patch cycle management",
        "software update process", "firmware update procedure", "patch tuesday planning",
        "critical fix deployment", "vulnerability patching", "change control process",
        "release management"
    }},

    {"Red Teaming", {
        "red team exercise", "penetration testing", "ethical hacking assessment",
        "exploit simulation", "red team operation", "adversary emulation",
        "attack simulation", "physical intrusion testing", "social engineering assessment",
        "vulnerability assessment"
    }},

    {"Blue Teaming", {
        "blue team strategy", "defensive implementation", "security monitoring",
        "incident detection system", "response planning", "log analysis",
        "event triage process", "network defense system", "endpoint protection",
        "proactive defense strategy", "incident preparation"
    }},

    {"Bug Bounty", {
        "bug bounty program", "vulnerability disclosure policy", "security researcher management",
        "bugcrowd integration", "hackerone platform", "program policy development",
        "responsible disclosure", "coordinated disclosure", "bounty payout",
        "security reward", "hall of fame", "vulnerability submission", "scope definition"
    }},

    {"Security Architecture", {
        "security architecture design", "security design pattern", "threat modeling process",
        "secure design principle", "architectural risk assessment", "security pattern implementation",
        "reference architecture", "layered security approach", "system security modeling",
        "architecture flaw detection", "secure component design"
    }},

    {"DDoS Protection", {
        "ddos mitigation", "dos prevention", "rate limiting implementation", 
        "traffic throttling", "load balancer configuration", "cloudflare protection",
        "akamai security", "traffic spike management", "http flood prevention",
        "amplification protection", "botnet detection", "reflected attack prevention",
        "volumetric attack mitigation", "application-layer protection", "ddos appliance"
    }},

    {"Web Application Firewall", {
        "waf configuration", "waf rule implementation", "waf bypass prevention", 
        "modsecurity setup", "signature rule management", "payload filtering",
        "web protection system", "application filtering", "sql injection blocking",
        "xss filtering", "http anomaly detection"
    }},

    {"System Compromise", {
        "system breach", "system takeover", "host compromise", "server compromise",
        "system control", "remote system access", "unauthorized system access",
        "system infiltration", "compromised host", "compromised server",
        "system security breach", "system integrity loss", "system control gain",
        "unauthorized control", "system access gain", "privileged system access",
        "system security compromise", "system exploitation", "system penetration",
        "complete system access", "system ownership", "root access gained",
        "administrator access gained", "system command execution", "system shell access",
        "system backdoor", "persistent system access", "system control maintained",
        "compromised system pivot", "system security bypass"
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

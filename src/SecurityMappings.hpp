#pragma once

#include <string>
#include <unordered_map>

struct SecurityClassification {
    std::string label;
    float severity;
    std::string description;
};

// Define security classifications with severity weights
inline std::unordered_map<std::string, SecurityClassification> createSecurityMappings() {
    std::unordered_map<std::string, SecurityClassification> mappings;
    
    // Critical Security Terms (0.9 - 1.0)
    mappings["hasWeakCreds"] = {
        "Weak Credentials",
        0.95f,
        "Presence of weak, default, or compromised credentials"
    };
    
    mappings["isPatched"] = {
        "Patch Status",
        0.95f,
        "System patch and update status"
    };

    mappings["hasRootAccess"] = {
        "Root/Admin Access",
        1.0f,
        "Elevated/administrative privileges obtained"
    };

    mappings["hasVulnerability"] = {
        "Known Vulnerability",
        0.9f,
        "Presence of known security vulnerability"
    };

    // High Severity Terms (0.7 - 0.8)
    mappings["hasSSH"] = {
        "SSH Service",
        0.8f,
        "SSH service availability"
    };

    mappings["isOpen"] = {
        "Open Service",
        0.75f,
        "Service or port accessibility"
    };

    mappings["hasEncryption"] = {
        "Encryption Status",
        0.8f,
        "Data encryption status"
    };

    mappings["hasSensitiveData"] = {
        "Sensitive Data",
        0.8f,
        "Presence of sensitive or critical data"
    };

    // Medium Severity Terms (0.4 - 0.6)
    mappings["hasTools"] = {
        "Security Tools",
        0.6f,
        "Presence of security/attack tools"
    };

    mappings["hasFirewall"] = {
        "Firewall Status",
        0.6f,
        "Firewall configuration status"
    };

    mappings["hasAuditLog"] = {
        "Audit Logging",
        0.5f,
        "System audit and logging status"
    };

    mappings["hasBackup"] = {
        "Backup Status",
        0.5f,
        "Data backup availability"
    };

    // Low Severity Terms (0.1 - 0.3)
    mappings["hasDocumentation"] = {
        "Documentation",
        0.3f,
        "Security documentation status"
    };

    mappings["hasTraining"] = {
        "Security Training",
        0.3f,
        "Security awareness and training status"
    };

    mappings["hasPolicy"] = {
        "Security Policy",
        0.2f,
        "Security policy implementation status"
    };

    // Network Terms (0.4 - 0.8)
    mappings["hasNetworkAccess"] = {
        "Network Access",
        0.7f,
        "Network accessibility status"
    };

    mappings["hasSegmentation"] = {
        "Network Segmentation",
        0.6f,
        "Network segmentation status"
    };

    mappings["hasDMZ"] = {
        "DMZ Implementation",
        0.5f,
        "Demilitarized zone status"
    };

    // Access Control Terms (0.5 - 0.9)
    mappings["hasMFA"] = {
        "Multi-Factor Auth",
        0.8f,
        "Multi-factor authentication status"
    };

    mappings["hasAccessControl"] = {
        "Access Controls",
        0.7f,
        "Access control implementation"
    };

    mappings["hasPrivileges"] = {
        "Privilege Level",
        0.8f,
        "User/system privilege status"
    };

    return mappings;
} 
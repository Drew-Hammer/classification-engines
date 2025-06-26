#pragma once

#include <map>
#include <string>
#include <vector>

namespace exposure {

// Severity scores for each category (0.1 to 0.95)
// Higher scores indicate greater exposure risk
const std::map<std::string, double> CATEGORY_SEVERITY = {
    // CRITICAL (0.85-0.95) - Direct exposure to internet/public
    {"Internet Exposure", 0.95},          
    {"Credential Exposure", 0.90},         
    {"Sensitive Data Exposure", 0.90},     // PII, financial data, etc exposed
    {"Network Exposure", 0.80},            // Network level exposure
    {"API Exposure", 0.80},                // Exposed APIs and endpoints
    
    // HIGH (0.70-0.84) - Significant exposure surface
    {"Cloud Resource Exposure", 0.75},     // Exposed cloud resources
    {"Container Exposure", 0.75},          // Container-related exposures
    {"Service Exposure", 0.70},            // Exposed internal services
    
    // MEDIUM (0.50-0.69) - Limited exposure
    {"Configuration Exposure", 0.65},      // Exposed configs and settings
    {"Infrastructure Exposure", 0.60},     // Exposed infrastructure details
    {"Debug Exposure", 0.55},             // Debug/trace information exposure
    
    // LOW (0.30-0.49) - Minimal exposure
    {"Internal Exposure", 0.45},          // Internal system exposure
    {"Documentation Exposure", 0.35}      // Exposed internal documentation
};

// Keywords associated with each category
const std::map<std::string, std::vector<std::string>> CATEGORY_KEYWORDS = {
    {"Internet Exposure", {
        "public endpoint", "internet facing", "external access",
        "public ip", "exposed port", "open port", "public url",
        "public dns", "public domain", "public website",
        "public api", "public service", "internet accessible",
        "world accessible", "globally accessible", "public facing",
        "external interface", "public interface", "exposed interface",
        "internet exposure", "public exposure", "external exposure"
    }},

    {"Credential Exposure", {
        "password", "api key", "secret key", "access key",
        "token", "credential", "authentication key",
        "private key", "ssh key", "encryption key",
        "certificate", "oauth token", "jwt token",
        "basic auth", "plaintext password", "hardcoded credential",
        "exposed secret", "leaked credential", "visible password"
    }},

    {"Sensitive Data Exposure", {
        "pii", "personal data", "sensitive data",
        "credit card", "social security", "bank account",
        "health record", "medical data", "financial data",
        "confidential data", "private data", "restricted data",
        "classified data", "proprietary data", "trade secret",
        "intellectual property", "customer data", "user data"
    }},

    {"Network Exposure", {
        "open port", "exposed service", "network access",
        "public endpoint", "network interface", "exposed interface",
        "network exposure", "port exposure", "service exposure",
        "tcp exposure", "udp exposure", "protocol exposure",
        "network visibility", "exposed protocol", "network access"
    }},

    {"API Exposure", {
        "api endpoint", "rest api", "graphql api",
        "public api", "exposed endpoint", "api access",
        "api key", "api token", "api credential",
        "api documentation", "swagger", "openapi",
        "api specification", "api interface", "api exposure"
    }},

    {"Cloud Resource Exposure", {
        "s3 bucket", "blob storage", "cloud storage",
        "cloud instance", "cloud service", "cloud resource",
        "cloud endpoint", "cloud api", "cloud interface",
        "cloud exposure", "aws resource", "azure resource",
        "gcp resource", "cloud access", "cloud visibility"
    }},

    {"Container Exposure", {
        "docker", "container", "kubernetes",
        "pod", "container registry", "container image",
        "container service", "container endpoint", "container interface",
        "container exposure", "container access", "container visibility",
        "exposed container", "public container", "container port"
    }},

    {"Service Exposure", {
        "microservice", "web service", "service endpoint",
        "service interface", "service api", "service port",
        "service exposure", "exposed service", "public service",
        "service access", "service visibility", "service discovery"
    }},

    {"Configuration Exposure", {
        "config file", "configuration", "settings file",
        "environment variable", "env var", "config parameter",
        "config value", "config setting", "exposed config",
        "visible config", "public config", "configuration exposure"
    }},

    {"Infrastructure Exposure", {
        "infrastructure", "server", "host",
        "instance", "machine", "node",
        "cluster", "datacenter", "infrastructure component",
        "infrastructure exposure", "exposed infrastructure", "visible infrastructure"
    }},

    {"Debug Exposure", {
        "debug log", "trace log", "debug info",
        "stack trace", "error message", "debug output",
        "debug interface", "debug port", "debug endpoint",
        "debug exposure", "exposed debug", "visible debug"
    }},

    {"Internal Exposure", {
        "internal service", "internal endpoint", "internal api",
        "internal interface", "internal port", "internal access",
        "internal exposure", "exposed internal", "visible internal"
    }},

    {"Documentation Exposure", {
        "documentation", "api doc", "technical doc",
        "internal doc", "system doc", "architecture doc",
        "design doc", "implementation doc", "code doc",
        "doc exposure", "exposed doc", "visible doc"
    }}
};

// Structure to hold category scoring information
struct CategoryScore {
    std::string category;
    float confidence;
    float severity;
    std::vector<std::pair<std::string, float>> matching_terms;

    // Default constructor
    CategoryScore() : category(""), confidence(0.0f), severity(0.0f) {}

    CategoryScore(const std::string& cat, float conf) 
        : category(cat), confidence(conf), severity(0.0f) {}
};

} // namespace exposure

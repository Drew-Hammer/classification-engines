#pragma once

#include <map>
#include <string>
#include <vector>

namespace exposure {

// Severity scores for each category (0.1 to 0.95)
// Higher scores indicate greater exposure risk
const std::map<std::string, double> CATEGORY_SEVERITY = {
    // CRITICAL (0.85-0.95) - Direct exposure to internet/public
    {"Internet Exposure", 0.95},           // Directly accessible from internet
    {"Credential Exposure", 0.90},         // Exposed secrets, keys, passwords
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

const std::map<std::string, std::vector<std::string>> CATEGORY_KEYWORDS = {
    {"Internet Exposure", {
        "public endpoint", "internet facing", "external access",
        "public ip", "public dns", "public url",
        "internet accessible", "publicly available", "public subnet",
        "exposed port", "open port", "port exposure",
        "public interface", "external interface", "internet gateway",
        "public api", "public service", "public endpoint",
        "world readable", "world accessible", "global access",
        "public access", "anonymous access", "unauthenticated access",
        "internet traffic", "inbound traffic", "external traffic",
        "public route", "public routing", "public network",
        "dmz exposure", "perimeter network", "edge network"
    }},

    {"Credential Exposure", {
        "exposed key", "exposed secret", "exposed token",
        "exposed password", "exposed credential", "exposed api key",
        "leaked key", "leaked secret", "leaked token",
        "leaked password", "leaked credential", "leaked certificate",
        "hardcoded credential", "hardcoded secret", "hardcoded key",
        "plaintext password", "plaintext secret", "plaintext credential",
        "exposed auth", "exposed authentication", "exposed authorization",
        "public key leak", "private key leak", "ssh key exposure",
        "aws key exposure", "access key leak", "secret key leak",
        "token leak", "bearer token", "access token",
        "credential file", "password file", ".env file",
        "configuration leak", "config exposure", "settings exposure"
    }},

    {"Sensitive Data Exposure", {
        "pii exposure", "personal data", "sensitive information",
        "financial data", "health data", "confidential data",
        "proprietary data", "trade secret", "intellectual property",
        "customer data", "user data", "account data",
        "data leak", "information leak", "data exposure",
        "sensitive file", "sensitive document", "sensitive record",
        "data breach", "information disclosure", "data disclosure",
        "exposed database", "exposed storage", "exposed backup",
        "sensitive log", "sensitive trace", "sensitive debug",
        "phi exposure", "pci data", "classified data"
    }},

    {"Network Exposure", {
        "open port", "exposed service", "network access",
        "unrestricted port", "unfiltered traffic", "bypass firewall",
        "network visibility", "network exposure", "network access",
        "exposed protocol", "protocol exposure", "service discovery",
        "network scan", "port scan", "service enumeration",
        "network mapping", "topology exposure", "routing exposure",
        "exposed socket", "socket exposure", "tcp exposure",
        "udp exposure", "protocol leak", "network leak",
        "exposed interface", "interface exposure", "network interface"
    }},

    {"API Exposure", {
        "api endpoint", "exposed api", "public api",
        "rest endpoint", "graphql endpoint", "soap endpoint",
        "api access", "api exposure", "endpoint exposure",
        "api gateway", "api proxy", "api route",
        "exposed method", "exposed function", "exposed operation",
        "api documentation", "swagger exposure", "openapi exposure",
        "api key", "api token", "api credential",
        "api authentication", "api authorization", "api security",
        "endpoint leak", "endpoint disclosure", "api disclosure"
    }},

    {"Cloud Resource Exposure", {
        "exposed bucket", "public bucket", "exposed blob",
        "exposed instance", "public instance", "exposed volume",
        "cloud storage", "object storage", "storage access",
        "cloud function", "serverless exposure", "lambda exposure",
        "cloud api", "cloud endpoint", "cloud service",
        "cloud resource", "cloud asset", "cloud infrastructure",
        "aws exposure", "azure exposure", "gcp exposure",
        "cloud credential", "cloud config", "cloud setting",
        "iam exposure", "role exposure", "permission exposure"
    }},

    {"Container Exposure", {
        "exposed container", "container access", "docker exposure",
        "kubernetes exposure", "k8s exposure", "pod exposure",
        "container registry", "registry access", "image exposure",
        "container secret", "container config", "container mount",
        "container volume", "container network", "container port",
        "container api", "container endpoint", "container service",
        "container runtime", "container host", "container escape",
        "privileged container", "container capability", "container permission"
    }},

    {"Service Exposure", {
        "exposed service", "service access", "service endpoint",
        "internal service", "microservice exposure", "service discovery",
        "service interface", "service api", "service port",
        "service route", "service proxy", "service gateway",
        "service mesh", "mesh exposure", "mesh traffic",
        "service authentication", "service authorization", "service security",
        "service credential", "service config", "service setting"
    }},

    {"Configuration Exposure", {
        "exposed config", "config leak", "setting exposure",
        "configuration file", "config file", "setting file",
        "environment variable", "env var", "env file",
        "exposed setting", "setting leak", "parameter exposure",
        "config disclosure", "setting disclosure", "parameter disclosure",
        "system config", "app config", "application setting",
        "exposed parameter", "parameter leak", "configuration leak"
    }},

    {"Infrastructure Exposure", {
        "infrastructure detail", "system information", "version information",
        "server detail", "host detail", "platform detail",
        "architecture exposure", "topology exposure", "infrastructure map",
        "system version", "software version", "framework version",
        "technology stack", "tech stack", "infrastructure stack",
        "system architecture", "deployment detail", "infrastructure config"
    }},

    {"Debug Exposure", {
        "debug log", "trace log", "verbose log",
        "debug output", "trace output", "debug information",
        "stack trace", "error trace", "exception detail",
        "debug mode", "debug flag", "debug setting",
        "diagnostic data", "diagnostic output", "diagnostic log",
        "development flag", "development mode", "debug endpoint"
    }},

    {"Internal Exposure", {
        "internal endpoint", "internal service", "internal api",
        "internal route", "internal path", "internal resource",
        "internal access", "internal visibility", "internal exposure",
        "internal detail", "internal information", "internal data",
        "internal config", "internal setting", "internal parameter"
    }},

    {"Documentation Exposure", {
        "internal doc", "private doc", "confidential doc",
        "internal documentation", "private documentation", "system documentation",
        "architecture doc", "design doc", "implementation doc",
        "api doc", "service doc", "endpoint doc",
        "swagger doc", "openapi doc", "technical doc",
        "development doc", "internal guide", "private guide"
    }}
};

} // namespace exposure 
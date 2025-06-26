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

} // namespace exposure 
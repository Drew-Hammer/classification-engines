#include "classification_engine.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <utility>

int main() {
    // Test cases with different security-related terms
    std::vector<std::string> test_cases = {
        "hasSsh",
        "DevOps security issue",
        "malware detected",
        "normal non-security text",
        "SQL injection attempt",
        "password expired",
        "network firewall",
        "2FA authentication failed"
    };
    
    std::cout << "Testing Classification Engine\n";
    std::cout << "===========================\n\n";
    
    for (const auto& text : test_cases) {
        double severity = classifyText(text);
        
        std::cout << "Text: \"" << text << "\"\n";
        std::cout << "Severity: " << std::fixed << std::setprecision(2) 
                  << (severity * 100) << "%";
        
        // Add severity level indicator
        if (severity >= 0.8) std::cout << " (HIGH)";
        else if (severity >= 0.6) std::cout << " (MEDIUM)";
        else std::cout << " (LOW)";
        
        std::cout << "\n\n";
    }
    
    return 0;
} 
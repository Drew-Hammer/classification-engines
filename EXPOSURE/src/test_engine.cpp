#include "classification_engine.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <utility>

int main() {
    // Set the correct model directory
    setModelDirectory("models");
    
    // Test cases with different security-related terms
    std::vector<std::string> test_cases = {
        "has ssh open",
        "DevOps security issue",
        "malware detected",
        "normal non-security text",
        "has packet capture",
        "sql Injection Attack",
        "network firewall",
        "Postcondition exploit Buffer Overflow changed has Port Scan using buffer Overflow Exploit",
        "Changed has Port Scan",
        "vulnerability detected",
        "logging issues"
    };
    
    std::cout << "Testing Classification Engine\n";
    std::cout << "===========================\n\n";
    
    for (const auto& text : test_cases) {
        double severity = classifyText(text);
        
        std::cout << "Text: \"" << text << "\"\n";
        std::cout << "Severity: " << std::fixed << std::setprecision(2) 
                  << (severity * 100) << "%";
        
        std::cout << "\n\n";
    }
    
    return 0;
} 
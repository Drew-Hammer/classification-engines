#include "exposure_engine.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

int main() {
    std::vector<std::string> testCases = {
        "public api endpoint accessible from internet",
        "aws access key exposed in github repo",
        "sensitive customer data in public s3 bucket",
        "open port 22 on production server",
        "debug logs containing passwords",
        "internal documentation published on public wiki",
        "container registry with public access",
        "environment variables in docker logs",
        "stack trace exposed in error page",
        "service credentials in config.js"
    };
    
    std::cout << "Testing Exposure Classification\n";
    std::cout << "===========================\n\n";
    
    for (const auto& test : testCases) {
        std::cout << "Text: \"" << test << "\"\n";
        
        auto results = exposure::classifyExposure(test);
        if (!results.empty()) {
            std::cout << "Severity: " << std::fixed << std::setprecision(2) 
                      << (results[0].second * 100) << "%\n";
        } else {
            std::cout << "Severity: 0.00%\n";
        }
        std::cout << "\n";
    }
    
    return 0;
} 
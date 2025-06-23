#include "PriorityScoring.hpp"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <cmath>

// Helper function to round to n decimal places
inline double roundToNDecimals(double value, int decimals) {
    const double multiplier = std::pow(10.0, decimals);
    return std::round(value * multiplier) / multiplier;
}

// Default config version - from file
bool PriorityScoring::processNetworkPriorities(const std::string& inputPath, bool writeToFile, bool verbose) {
    return processNetworkPriorities(inputPath, PriorityConfig(), writeToFile, verbose);
}

// Default config version - from json
bool PriorityScoring::processNetworkPriorities(json& network, bool verbose) {
    return processNetworkPriorities(network, PriorityConfig(), verbose);
}

// Custom config version - from file
bool PriorityScoring::processNetworkPriorities(const std::string& inputPath, const PriorityConfig& config, bool writeToFile, bool verbose) {
    try {
        std::ifstream file(inputPath);
        if (!file.is_open()) {
            std::cerr << "Error: Could not open input json: " << inputPath << std::endl;
            return false;
        }
        
        json network;
        file >> network;
        file.close();

        // Create scorer with custom config
        PriorityScoring scorer(config);
        
        // Process each rule
        for (auto& rule : network["Rules"]) {
            double priority = scorer.calculateRulePriority(
                rule, 
                network["CommonProperties"], 
                network["Containers"]
            );
            
            rule["Priority"] = roundToNDecimals(priority, 3);
            
            if (verbose) {
                std::cout << "Rule: " << rule["Name"] << "\n";
                std::cout << "Priority Score: " << std::fixed << std::setprecision(3) << priority << "\n\n";
            }
        }
        
        if (writeToFile) {
            std::ofstream outFile(inputPath);
            if (!outFile.is_open()) {
                std::cerr << "Error: Could not open output file for writing: " << inputPath << std::endl;
                return false;
            }
            outFile << std::setw(2) << network << std::endl;
            outFile.close();
            
            if (verbose) {
                std::cout << "Successfully updated priority scores in " << inputPath << std::endl;
            }
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error processing network priorities: " << e.what() << std::endl;
        return false;
    }
}

// Custom config version - from json
bool PriorityScoring::processNetworkPriorities(json& network, const PriorityConfig& config, bool verbose) {
    try {
        // Create scorer with custom config
        PriorityScoring scorer(config);
        
        // Process each rule
        for (auto& rule : network["Rules"]) {
            double priority = scorer.calculateRulePriority(
                rule, 
                network["CommonProperties"], 
                network["Containers"]
            );
            
            
            rule["Priority"] = roundToNDecimals(priority, 3);
            
            if (verbose) {
                std::cout << "Rule: " << rule["Name"] << "\n";
                std::cout << "Priority Score: " << std::fixed << std::setprecision(3) << priority << "\n\n";
            }
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error processing network priorities: " << e.what() << std::endl;
        return false;
    }
} 
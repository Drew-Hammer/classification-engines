#pragma once

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "json.hpp"
#include "classification_engine.hpp"

using json = nlohmann::json;

struct PriorityConfig {
    double w_pre;
    double p_exponent;

    
    PriorityConfig() :
        w_pre(0.0335), 
        p_exponent(0.45)
    {}
};

class PriorityScoring {
public:
    PriorityScoring(const PriorityConfig& config = PriorityConfig());
    
    // Main function to calculate rule priority score
    double calculateRulePriority(const json& rule, const json& commonProperties, const json& containers);

    // Gateway functions declarations - with default config
    static bool processNetworkPriorities(const std::string& inputPath, bool writeToFile = true, bool verbose = false);
    static bool processNetworkPriorities(json& network, bool verbose = false);

    // Gateway functions declarations - with custom config
    static bool processNetworkPriorities(const std::string& inputPath, const PriorityConfig& config, bool writeToFile = true, bool verbose = false);
    static bool processNetworkPriorities(json& network, const PriorityConfig& config, bool verbose = false);

private:
    PriorityConfig config;
    
    // Helper functions
    int countPreconditions(const json& rule);
    std::vector<double> calculatePostconditionScores(const json& rule, const json& commonProperties, const json& containers);
    double calculateSummedScore(const std::vector<double>& scores);
    double getGammaForRule(const json& rule);
}; 
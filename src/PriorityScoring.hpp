#pragma once

#include <vector>
#include <string>
#include "json.hpp"
#include "classification_engine.hpp"

using json = nlohmann::json;

struct PriorityConfig {
    double w_pre;      // Weight for preconditions
    double epsilon;    // Small constant
    double p_exponent; // p value for position-based weighting

    // Default constructor with initial values
    PriorityConfig() :
        w_pre(0.4316),
        epsilon(0.0001),
        p_exponent(0.5)
    {}
};

class PriorityScoring {
public:
    PriorityScoring(const PriorityConfig& config = PriorityConfig());
    
    // Main function to calculate rule priority score
    double calculateRulePriority(const json& rule, const json& commonProperties, const json& containers);

private:
    PriorityConfig config;
    
    // Helper functions
    int countPreconditions(const json& rule);
    std::vector<double> calculatePostconditionScores(const json& rule, const json& commonProperties, const json& containers);
    double calculateSummedScore(const std::vector<double>& scores);
    double getGammaForRule(const json& rule);
}; 
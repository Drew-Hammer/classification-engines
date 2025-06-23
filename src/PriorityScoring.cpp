#include "PriorityScoring.hpp"
#include <cmath>
#include <algorithm>
#include <numeric>
#include <iostream>
#include <iomanip>
#include <fstream>

PriorityScoring::PriorityScoring(const PriorityConfig& config) : config(config) {}

double PriorityScoring::getGammaForRule(const json& rule) {
    std::string ruleType = rule["RuleType"].get<std::string>();
    return (ruleType == "GenericRule") ? 1.1 : 1.0;
}

double PriorityScoring::calculateRulePriority(const json& rule, const json& commonProperties, const json& containers) {
    // Calculate S_post (vector of postcondition scores)
    std::vector<double> s_post = calculatePostconditionScores(rule, commonProperties, containers);
    
    // If no postconditions, return 0
    if (s_post.empty()) {
        return 0.0;
    }

    //Sum function inside of Ri term
    double sum = 0.0;
    for (size_t j = 0; j < s_post.size(); j++) {
        double delta = (s_post[j] > 0.9) ? 0.05 : 0.0;
        double position_weight = 1.0 / std::pow(j + 1, config.p_exponent); 
        // std::cout << "Position weight: " << position_weight << std::endl;
        sum += (s_post[j] * (1.0 + delta)) * position_weight;
    }
    double avg_score = sum / static_cast<double>(s_post.size());

    // Calculate precondition weight using new formula: max(0.6, 1.15 - w_pre * (n_pre - 1))
    int n_pre = countPreconditions(rule);
    double pre_weight = std::max(0.6, 1.06 - config.w_pre * (n_pre - 1));
    
    // Apply gamma for generic boost factor
    double gamma = getGammaForRule(rule);
    
    // std::cout << "Average score: " << avg_score << std::endl;
    // std::cout << "Precondition weight: " << pre_weight << std::endl;
    // std::cout << "With precondition weight: " << pre_weight * avg_score << std::endl;
    // std::cout << "With Gamma: " << pre_weight * gamma << std::endl;
    // std::cout << "Final score: " << pre_weight * gamma * avg_score << std::endl;
    
    return pre_weight * gamma * avg_score;
}

int PriorityScoring::countPreconditions(const json& rule) {
    int totalPreconditions = 0;
    std::string ruleType = rule["RuleType"].get<std::string>();
    
    if (ruleType == "GenericRule") {
        if (rule.contains("StartContainerPreConditions")) {
            totalPreconditions += rule["StartContainerPreConditions"].size();
        }
        if (rule.contains("LinkPreConditions")) {
            totalPreconditions += rule["LinkPreConditions"].size();
        }
        if (rule.contains("EndContainerPreConditions")) {
            totalPreconditions += rule["EndContainerPreConditions"].size();
        }
    } else {
        if (rule.contains("PreConditions")) {
            totalPreconditions += rule["PreConditions"].size();
        }
    }
    
    return totalPreconditions;
}

std::vector<double> PriorityScoring::calculatePostconditionScores(const json& rule, const json& commonProperties, const json& containers) {
    std::vector<double> scores;
    json postconditions;
    
    // Get postconditions based on rule type
    if (rule["RuleType"].get<std::string>() == "GenericRule") {
        if (rule.contains("EndContainerPostConditions")) {
            postconditions = rule["EndContainerPostConditions"];
        }
    } else {
        if (rule.contains("PostConditions")) {
            postconditions = rule["PostConditions"];
        }
    }

    // Process each postcondition
    for (const auto& postcondition : postconditions) {
        std::string factName;
        if (postcondition["IsFact"].get<bool>()) {
            // Get fact name from containers
            for (const auto& container : containers) {
                for (const auto& fact : container["Facts"]) {
                    if (fact["Id"] == postcondition["ReferenceId"]) {
                        factName = fact["Name"].get<std::string>();
                        break;
                    }
                }
                if (!factName.empty()) break;
            }
        } else {
            // Get property name from commonProperties
            for (const auto& prop : commonProperties) {
                if (prop["Id"] == postcondition["ReferenceId"]) {
                    factName = std::string("Target System ") + prop["Name"].get<std::string>();
                    break;
                }
            }
        }

        if (!factName.empty()) {
            double score = classifyText(factName, "models");
            scores.push_back(score);
        }
    }

    return scores;
}

double PriorityScoring::calculateSummedScore(const std::vector<double>& scores) {
    return std::accumulate(scores.begin(), scores.end(), 0.0);
} 
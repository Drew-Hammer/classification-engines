#include "PriorityScoring.hpp"
#include <cmath>
#include <algorithm>
#include <numeric>

PriorityScoring::PriorityScoring(const PriorityConfig& config) : config(config) {}

double PriorityScoring::getGammaForRule(const json& rule) {
    std::string ruleType = rule["RuleType"].get<std::string>();
    return (ruleType == "GenericRule") ? 1.1 : 1.0;
}

double PriorityScoring::calculateRulePriority(const json& rule, const json& commonProperties, const json& containers) {
    // Get N_pre (number of preconditions)
    int n_pre = countPreconditions(rule);
    
    // Calculate S_post (vector of postcondition scores)
    std::vector<double> s_post = calculatePostconditionScores(rule, commonProperties, containers);
    
    // Sort postcondition scores in descending order
    std::sort(s_post.begin(), s_post.end(), std::greater<double>());
    
    // If no postconditions, return 0
    if (s_post.empty()) {
        return 0.0;
    }

    // Calculate the sum with position-based weighting and high severity bonus
    double sum = 0.0;
    for (size_t j = 0; j < s_post.size(); ++j) {
        double delta = (s_post[j] > 0.9) ? 0.05 : 0.0;
        double position_weight = 1.0 / std::pow(j + 1, config.p_exponent);
        sum += (s_post[j] * (1.0 + delta)) * position_weight;
    }

    // Calculate average by dividing by n
    double avg_score = sum / static_cast<double>(s_post.size());

    // Calculate final score using the Ri formula with rule-specific gamma
    double pre_term = config.w_pre / (n_pre + config.epsilon);
    double gamma = getGammaForRule(rule);
    
    return pre_term * gamma * avg_score;
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
            // Create a more specific impact description based on the fact name
            std::string impactStr;
            if (factName.find("Log") != std::string::npos) {
                impactStr = "audit log tampering: " + factName;
            } else if (factName.find("Configuration") != std::string::npos) {
                impactStr = "configuration change: " + factName;
            } else if (factName.find("Root Access") != std::string::npos || 
                      factName.find("Administrator") != std::string::npos) {
                impactStr = "system compromise: " + factName;
            } else if (factName.find("Data") != std::string::npos) {
                impactStr = "data breach: " + factName;
            } else {
                impactStr = "impact: " + factName;
            }
            
            double score = classifyText(impactStr, "models");
            scores.push_back(score);
        }
    }

    return scores;
}

double PriorityScoring::calculateSummedScore(const std::vector<double>& scores) {
    return std::accumulate(scores.begin(), scores.end(), 0.0);
} 
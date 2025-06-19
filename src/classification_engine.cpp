#include "Classifier.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <cmath>

// Static variable to store model directory
static std::string model_directory = "../models";

// Function to set model directory
void setModelDirectory(const std::string& directory) {
    model_directory = directory;
    // Remove trailing slash if present
    if (!model_directory.empty() && model_directory.back() == '/') {
        model_directory.pop_back();
    }
}

// Function to classify text and return severity score
double classifyText(const std::string& text, const std::string& model_dir) {
    static Classifier classifier;
    static bool initialized = false;
    
    // Use provided model_dir if not empty, otherwise use the static model_directory
    std::string dir = model_dir.empty() ? model_directory : model_dir;
    // Remove trailing slash if present
    if (!dir.empty() && dir.back() == '/') {
        dir.pop_back();
    }
    
    // Initialize classifier only once
    if (!initialized) {
        if (!classifier.initialize(dir + "/security_model.bin")) {
            std::cerr << "Failed to load security model, trying to load full model...\n";
            if (!classifier.initialize(dir + "/wiki.en.bin")) {
                std::cerr << "Failed to initialize classifier" << std::endl;
                return -1.0;
            }
        }
        initialized = true;
    }
    
    // Classify the text
    auto result = classifier.classifyWord(text);
    
    // Calculate weighted average severity from top 3 categories
    double total_weighted_severity = 0.0;
    double total_weights = 0.0;
    
    // Sort all_scores by confidence
    std::sort(result.all_scores.begin(), result.all_scores.end(),
              [](const auto& a, const auto& b) { return a.confidence > b.confidence; });
    
    // Take top 3 categories or all if less than 3
    for (size_t i = 0; i < std::min(size_t(3), result.all_scores.size()); ++i) {
        if (result.all_scores[i].confidence > 0.0f) {
            // More conservative position weighting: 1.0, 0.3, 0.1 for positions 0,1,2
            double position_weight = std::pow(0.3, i);  // Steeper decay
            
            // Linear severity to avoid over-amplifying high severities
            double severity_weight = result.all_scores[i].severity;
            
            // Penalize partial matches more heavily
            double confidence_boost = result.all_scores[i].confidence * result.all_scores[i].confidence;  // Square to penalize low confidence
            
            // Additional penalty for very low confidence matches
            if (result.all_scores[i].confidence < 0.7) {
                confidence_boost *= 0.5;  // 50% penalty for low confidence matches
            }
            
            double combined_weight = position_weight * severity_weight * confidence_boost;
            
            total_weighted_severity += result.all_scores[i].severity * combined_weight;
            total_weights += combined_weight;
        }
    }
    
    // Return weighted average severity with 3 decimal places precision
    double final_severity = total_weights > 0.0 ? total_weighted_severity / total_weights : 0.0;
    return std::round(final_severity * 1000.0) / 1000.0;  // Round to 3 decimal places
} 
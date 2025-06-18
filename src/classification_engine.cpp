#include "Classifier.hpp"
#include <iostream>
#include <iomanip>

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
    
    // Return the severity score as a double between 0 and 1
    return result.severity;
} 
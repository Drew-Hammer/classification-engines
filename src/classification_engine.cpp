#include "Classifier.hpp"
#include <iostream>
#include <iomanip>

// Function to classify text and return severity score
double classifyText(const std::string& text) {
    static Classifier classifier;
    static bool initialized = false;
    
    // Initialize classifier only once
    if (!initialized) {
        if (!classifier.initialize("../models/security_model.bin")) {
            std::cerr << "Failed to load security model, trying to load full model...\n";
            if (!classifier.initialize("../models/wiki.en.bin")) {
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
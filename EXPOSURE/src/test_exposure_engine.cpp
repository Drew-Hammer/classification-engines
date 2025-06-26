#include "ExposureClassifier.hpp"
#include "exposure_engine.hpp"
#include <iostream>
#include <iomanip>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " \"phrase to classify\"" << std::endl;
        return 1;
    }

    exposure::ExposureClassifier classifier;
    
    // Initialize the classifier with the model
    if (!classifier.initialize("./models/exposure_model.vec")) {
        std::cerr << "Failed to load exposure model" << std::endl;
        return 1;
    }

    // Get the phrase from command line argument
    std::string phrase = argv[1];
    
    // Classify the phrase
    auto result = classifier.classifyWord(phrase);
    
    // Print the results
    std::cout << "\nExposure Classification Results for '" << phrase << "':\n";
    std::cout << std::string(60, '-') << "\n";
    std::cout << "Category:   " << result.category << "\n";
    std::cout << "Confidence: " << std::fixed << std::setprecision(2) 
              << (result.confidence * 100) << "%\n";
    std::cout << "Severity:   " << std::fixed << std::setprecision(2) 
              << (result.severity * 100) << "%";
    
    // Add severity level indicator
    if (result.severity >= 0.8f) std::cout << " (HIGH)";
    else if (result.severity >= 0.6f) std::cout << " (MEDIUM)";
    else std::cout << " (LOW)";
    std::cout << "\n\n";

    // Show matching terms if any
    if (!result.similar_terms.empty()) {
        std::cout << "Similar Terms:\n";
        int count = 0;
        for (const auto& [term, score] : result.similar_terms) {
            std::cout << "  • " << term << " (similarity: " 
                      << std::fixed << std::setprecision(2) 
                      << (score * 100) << "%)\n";
            if (++count >= 3) break;  // Show top 3 similar terms
        }
    }

    // Also test the exposure_engine function
    std::cout << "\nExposure Engine Score: " << std::fixed << std::setprecision(3) 
              << classifyExposure(phrase) << "\n";

    return 0;
} 
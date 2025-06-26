#include "ExposureClassifier.hpp"
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <array>
#include <sstream>
#include <algorithm>
#include <iostream>

namespace exposure {

Classifier::Classifier() {}

Classifier::~Classifier() {}

bool Classifier::init(const std::string& modelPath) {
    modelPath_ = modelPath;
    // Verify model exists
    FILE* f = fopen(modelPath.c_str(), "r");
    if (!f) {
        std::cerr << "Error: Could not open model file: " << modelPath << std::endl;
        return false;
    }
    fclose(f);
    return true;
}

std::vector<std::pair<std::string, double>> Classifier::classify(const std::string& text) {
    std::string processedText = textProcessor_.normalize(text);
    
    // Use full path to fasttext
    std::string fasttext_path = "./fastText/fasttext";
    
    // Prepare the command to run the fasttext predict with probability output
    std::string cmd = "echo \"" + processedText + "\" | " + fasttext_path + " predict-prob " + modelPath_ + " - 1 2>/dev/null";
    
    // std::cout << "Debug: Running command: " << cmd << std::endl;
    
    // Execute the command and get output
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    
    if (!pipe) {
        std::cerr << "Error: Failed to execute fasttext command" << std::endl;
        return {};
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    
    if (result.empty()) {
        std::cerr << "Warning: No output from fasttext" << std::endl;
    }
    
    return parseModelOutput(result);
}

std::vector<std::vector<std::pair<std::string, double>>> Classifier::classifyBatch(
    const std::vector<std::string>& texts) {
    std::vector<std::vector<std::pair<std::string, double>>> results;
    for (const auto& text : texts) {
        results.push_back(classify(text));
    }
    return results;
}

double Classifier::getCategorySeverity(const std::string& category) const {
    // std::cout << "Looking up severity for category: '" << category << "'" << std::endl;
    auto it = CATEGORY_SEVERITY.find(category);
    if (it != CATEGORY_SEVERITY.end()) {
        return it->second;
    }
    std::cout << "Category not found in CATEGORY_SEVERITY" << std::endl;
    return 0.0;
}

void Classifier::preprocessText(std::string& text) {
    text = textProcessor_.normalize(text);
}

std::vector<std::pair<std::string, double>> Classifier::parseModelOutput(const std::string& output) {
    std::vector<std::pair<std::string, double>> results;
    std::istringstream iss(output);
    std::string line;
    
    while (std::getline(iss, line)) {
        // Parse the fasttext output format
        size_t labelStart = line.find("__label__");
        if (labelStart != std::string::npos) {
            labelStart += 9; // Skip past "__label__"
            
            // Find the space after the label
            size_t labelEnd = line.find(" ", labelStart);
            if (labelEnd == std::string::npos) {
                labelEnd = line.length();
            }
            
            std::string category = line.substr(labelStart, labelEnd - labelStart);
            
            // Convert underscores back to spaces in category name
            std::replace(category.begin(), category.end(), '_', ' ');
            
            // Remove the word "exposure" if it exists at the end
            size_t exposurePos = category.find(" exposure");
            if (exposurePos != std::string::npos) {
                category = category.substr(0, exposurePos);
            }
            
            // Capitalize first letter of each word for consistency
            std::istringstream words(category);
            std::string word;
            std::string properCategory;
            while (words >> word) {
                if (!properCategory.empty()) properCategory += " ";
                properCategory += static_cast<char>(std::toupper(word[0])) + word.substr(1);
            }
            
            // Add "Exposure" to match the map keys
            std::string fullCategory = properCategory + " Exposure";
            // std::cout << "Looking up category: '" << fullCategory << "'" << std::endl;
            double severity = getCategorySeverity(fullCategory);
            
            // Store result with lowercase name for consistency with output
            results.emplace_back(category + "_exposure", severity);
        }
    }
    
    // Sort by severity
    std::sort(results.begin(), results.end(),
              [](const auto& a, const auto& b) {
                  return a.second > b.second;
              });
    
    return results;
}

} // namespace exposure 
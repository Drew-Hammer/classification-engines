#pragma once

#include <string>
#include <vector>
#include <map>
#include "TextProcessor.hpp"
#include "ExposureCategories.hpp"

namespace exposure {

class Classifier {
public:
    Classifier();
    ~Classifier();

    // Initialize the classifier with a model file
    bool init(const std::string& modelPath);

    // Classify a single text string
    std::vector<std::pair<std::string, double>> classify(const std::string& text);

    // Classify a batch of text strings
    std::vector<std::vector<std::pair<std::string, double>>> classifyBatch(
        const std::vector<std::string>& texts);

    // Get the severity score for a category
    double getCategorySeverity(const std::string& category) const;

private:
    // Internal methods
    void preprocessText(std::string& text);
    std::vector<std::pair<std::string, double>> parseModelOutput(const std::string& output);
    
    // Model path
    std::string modelPath_;
    
    // Text processor instance
    common::TextProcessor textProcessor_;
};

} // namespace exposure 
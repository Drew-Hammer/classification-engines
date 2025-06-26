#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <utility>
#include "ExposureCategories.hpp"

namespace exposure {

struct ExposureClassification {
    std::string category;
    float confidence;
    float severity;
    std::vector<std::pair<std::string, float>> similar_terms;
    std::vector<CategoryScore> all_scores;
};

class ExposureClassifier {
public:
    ExposureClassifier();
    ~ExposureClassifier();

    // Initialize with model file
    bool initialize(const std::string& modelPath, const std::set<std::string>& required_words = std::set<std::string>());
    
    // Save a subset of vectors
    bool saveSubset(const std::string& outputPath, const std::set<std::string>& words);
    
    // Main classification functions
    ExposureClassification classifyWord(const std::string& phrase, float threshold = 0.5f) const;
    std::vector<std::pair<std::string, double>> classify(const std::string& text);

    // Get severity score for a category
    double getCategorySeverity(const std::string& category) const;

private:
    // Internal helper functions
    std::vector<std::string> splitPhrase(const std::string& phrase) const;
    std::vector<float> getWordVector(const std::string& word) const;
    std::vector<float> getPhraseVector(const std::string& phrase) const;
    float getSimilarity(const std::string& word1, const std::string& word2) const;
    
    // Member variables
    size_t dimension_;
    std::map<std::string, std::vector<float>> word_vectors_;
};

} // namespace exposure
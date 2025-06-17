#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <set>
#include <utility>
#include <map>

constexpr float SIMILARITY_THRESHOLD = 0.45f;

struct CategoryScore {
    std::string category;
    float confidence;
    float severity;
    std::vector<std::pair<std::string, float>> matching_terms;

    CategoryScore() : confidence(0.0f), severity(0.0f) {}
    CategoryScore(const std::string& cat, float conf) 
        : category(cat), confidence(conf), severity(0.0f) {}
};

struct SecurityClassification {
    std::string category;                    // Primary category
    float confidence;                        // Overall confidence score
    float severity;                          // Overall severity score
    std::vector<CategoryScore> all_scores;   // Scores for all categories
    std::vector<std::pair<std::string, float>> similar_terms;  // Similar terms across all categories
};

class Classifier {
public:
    Classifier();
    ~Classifier();

    // Basic functionality
    bool initialize(const std::string& modelPath, const std::set<std::string>& required_words = {});
    bool saveSubset(const std::string& outputPath, const std::set<std::string>& words);
    
    // Core classification methods
    float getSimilarity(const std::string& word1, const std::string& word2) const;
    SecurityClassification classifyWord(const std::string& phrase, float threshold = 0.45f) const;

private:
    std::vector<float> getWordVector(const std::string& word) const;
    std::vector<float> getPhraseVector(const std::string& phrase) const;
    std::vector<std::string> splitPhrase(const std::string& phrase) const;
    
    std::unordered_map<std::string, std::vector<float>> word_vectors_;
    size_t dimension_;
};
#include "Classifier.hpp"
#include "SecurityCategories.hpp"
#include "TextProcessor.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cmath>
#include <algorithm>
#include <queue>
#include <map>

using security::CATEGORY_KEYWORDS;
using security::CATEGORY_SEVERITY;

Classifier::Classifier() : dimension_(0) {}

Classifier::~Classifier() = default;

bool Classifier::initialize(const std::string& modelPath, const std::set<std::string>& required_words) {
    // std::cout << "Attempting to load model from: " << modelPath << std::endl;
    
    std::ifstream in(modelPath, std::ios::binary);
    if (!in.is_open()) {
        std::cerr << "Cannot open model file: " << modelPath << std::endl;
        return false;
    }

    // std::cout << "Successfully opened model file" << std::endl;

    // Read header
    std::string line;
    std::getline(in, line);
    std::istringstream iss(line);
    size_t vocab_size;
    iss >> vocab_size >> dimension_;
    
    // std::cout << "Model header: vocab_size=" << vocab_size << ", dimension=" << dimension_ << std::endl;

    // Read word vectors
    size_t words_loaded = 0;
    bool load_all = required_words.empty();
    
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string word;
        iss >> word;

        // Skip words we don't need if we have a required set
        if (!load_all && required_words.find(word) == required_words.end()) {
            continue;
        }

        std::vector<float> vector(dimension_);
        for (size_t i = 0; i < dimension_; i++) {
            if (!(iss >> vector[i])) break;
        }
        
        if (word.length() > 0) {
            word_vectors_[word] = vector;
            words_loaded++;
            if (words_loaded % 100000 == 0) {
                std::cout << "Loaded " << words_loaded << " words..." << std::endl;
            }
        }

        // If we've found all required words, we can stop
        if (!load_all && word_vectors_.size() == required_words.size()) {
            break;
        }
    }

    // std::cout << "Finished loading " << word_vectors_.size() << " word vectors" << std::endl;
    return !word_vectors_.empty();
}

bool Classifier::saveSubset(const std::string& outputPath, const std::set<std::string>& words) {
    std::ofstream out(outputPath);
    if (!out.is_open()) {
        std::cerr << "Cannot open output file: " << outputPath << std::endl;
        return false;
    }

    // Write header
    out << words.size() << " " << dimension_ << std::endl;

    // Write vectors for specified words
    for (const auto& word : words) {
        auto it = word_vectors_.find(word);
        if (it != word_vectors_.end()) {
            out << word;
            for (float val : it->second) {
                out << " " << val;
            }
            out << std::endl;
        }
    }

    return true;
}

std::vector<std::string> Classifier::splitPhrase(const std::string& phrase) const {
    std::vector<std::string> words;
    std::istringstream iss(phrase);
    std::string word;
    while (iss >> word) {
        words.push_back(word);
    }
    return words;
}

std::vector<float> Classifier::getWordVector(const std::string& word) const {
    auto it = word_vectors_.find(word);
    if (it != word_vectors_.end()) {
        return it->second;
    }
    return std::vector<float>(dimension_, 0.0f);
}

std::vector<float> Classifier::getPhraseVector(const std::string& phrase) const {
    std::vector<float> result(dimension_, 0.0f);
    auto words = splitPhrase(phrase);
    if (words.empty()) return result;

    int valid_words = 0;
    for (const auto& word : words) {
        auto vec = getWordVector(word);
        if (vec != std::vector<float>(dimension_, 0.0f)) {
            for (size_t i = 0; i < dimension_; i++) {
                result[i] += vec[i];
            }
            valid_words++;
        }
    }

    // Average the vectors if we found any valid words
    if (valid_words > 0) {
        for (float& val : result) {
            val /= valid_words;
        }
    }

    return result;
}

float Classifier::getSimilarity(const std::string& word1, const std::string& word2) const {
    auto vec1 = getPhraseVector(word1);
    auto vec2 = getPhraseVector(word2);

    float dotProduct = 0.0f;
    float norm1 = 0.0f;
    float norm2 = 0.0f;

    for (size_t i = 0; i < dimension_; i++) {
        dotProduct += vec1[i] * vec2[i];
        norm1 += vec1[i] * vec1[i];
        norm2 += vec2[i] * vec2[i];
    }

    norm1 = std::sqrt(norm1);
    norm2 = std::sqrt(norm2);

    return (norm1 > 0 && norm2 > 0) ? dotProduct / (norm1 * norm2) : 0.0f;
}

SecurityClassification Classifier::classifyWord(const std::string& phrase, float threshold) const {
    SecurityClassification result;
    result.category = "Unknown";
    result.confidence = 0.0f;
    result.severity = 0.0f;

    // Get all possible variations of the input phrase
    auto combinations = TextProcessor::getAllWordCombinations(phrase);
    
    // Track scores for each category
    std::map<std::string, CategoryScore> category_scores;
    for (const auto& [category, _] : CATEGORY_KEYWORDS) {
        category_scores[category] = CategoryScore(category, 0.0f);
        // Set severity from CATEGORY_SEVERITY map
        auto severity_it = CATEGORY_SEVERITY.find(category);
        if (severity_it != CATEGORY_SEVERITY.end()) {
            category_scores[category].severity = severity_it->second;
        }
    }
    
    // First try exact matches
    int exact_matches = 0;
    for (const auto& word : combinations) {
        for (const auto& [category, keywords] : CATEGORY_KEYWORDS) {
            if (std::find(keywords.begin(), keywords.end(), word) != keywords.end()) {
                category_scores[category].confidence = 1.0f;
                category_scores[category].matching_terms.push_back({word, 1.0f});
                exact_matches++;
            }
        }
    }
    
    // If we don't have enough exact matches, try semantic matches with a higher threshold
    if (exact_matches < 3) {
        float semantic_threshold = threshold + 0.2f;  // Increase threshold for semantic matches
        for (const auto& word : combinations) {
            for (const auto& [category, keywords] : CATEGORY_KEYWORDS) {
                // Skip categories that already have exact matches
                if (category_scores[category].confidence == 1.0f) continue;
                
                for (const auto& keyword : keywords) {
                    float sim = getSimilarity(word, keyword);
                    if (sim > semantic_threshold) {
                        auto& cat_score = category_scores[category];
                        cat_score.matching_terms.push_back({keyword, sim});
                        cat_score.confidence = std::max(cat_score.confidence, sim);
                        
                        // Add to overall similar terms
                        result.similar_terms.push_back({keyword, sim});
                    }
                }
            }
        }
    }

    // Sort similar terms by score
    std::sort(result.similar_terms.begin(), result.similar_terms.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    // Add all non-zero confidence categories to result
    for (const auto& [category, score] : category_scores) {
        if (score.confidence > 0.0f) {
            // Sort matching terms for this category
            auto category_score = score;
            std::sort(category_score.matching_terms.begin(), 
                     category_score.matching_terms.end(),
                     [](const auto& a, const auto& b) { return a.second > b.second; });
            result.all_scores.push_back(category_score);
        }
    }

    // Sort categories by confidence
    std::sort(result.all_scores.begin(), result.all_scores.end(),
              [](const auto& a, const auto& b) { return a.confidence > b.confidence; });

    // Set the primary category and scores based on the highest confidence category
    if (!result.all_scores.empty()) {
        result.category = result.all_scores[0].category;
        result.confidence = result.all_scores[0].confidence;
        result.severity = result.all_scores[0].severity;
    }

    return result;
}

 
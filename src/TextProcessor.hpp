#ifndef TEXT_PROCESSOR_HPP
#define TEXT_PROCESSOR_HPP

#include <string>
#include <vector>
#include <set>
#include <map>

class TextProcessor {
public:
    // Convert text to lowercase and remove special characters
    static std::string normalize(const std::string& text);
    
    // Basic stemming rules for security terms
    static std::string stem(const std::string& word);
    
    // Enhanced lemmatization for security terms
    static std::string lemmatize(const std::string& word);
    
    // Generate n-grams from text
    static std::vector<std::string> generateNGrams(const std::string& text, size_t n);
    
    // Split text into words
    static std::vector<std::string> tokenize(const std::string& text);
    
    // Get all possible word combinations from a phrase
    static std::vector<std::string> getAllWordCombinations(const std::string& phrase);

    // Split camelCase word into individual words
    static std::vector<std::string> splitCamelCase(const std::string& word);

    // Expand abbreviations in text
    static std::vector<std::string> expandAbbreviations(const std::string& text);

    // Check if a string is an abbreviation
    static bool isAbbreviation(const std::string& text);

private:
    // Common security-related suffixes
    static const std::vector<std::string> COMMON_SUFFIXES;
    
    // Security abbreviations and their expansions
    static const std::map<std::string, std::vector<std::string>> SECURITY_ABBREVIATIONS;

    // Irregular verb forms for security context
    static const std::map<std::string, std::string> IRREGULAR_VERBS;
    
    // Common security-related word forms
    static const std::map<std::string, std::string> SECURITY_WORD_FORMS;
    
    // Helper function to check if word ends with suffix
    static bool endsWith(const std::string& word, const std::string& suffix);
    
    // Helper function to check if word starts with prefix
    static bool startsWith(const std::string& word, const std::string& prefix);
};

#endif // TEXT_PROCESSOR_HPP 
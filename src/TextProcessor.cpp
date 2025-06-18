#include "TextProcessor.hpp"
#include <algorithm>
#include <sstream>
#include <cctype>
#include <iostream>

const std::vector<std::string> TextProcessor::COMMON_SUFFIXES = {
    "ing", "tion", "sion", "ment", "ity", "ness", "able", "ible", "ize", "ise",
    "ed", "ly", "ful", "less", "er", "or", "ive", "al", "ic", "ous"
};

// Define security-related abbreviations and their expansions
const std::map<std::string, std::vector<std::string>> TextProcessor::SECURITY_ABBREVIATIONS = {
    {"2fa", {"two factor authentication"}},
    {"acl", {"access control list"}},
    {"apt", {"advanced persistent threat"}},
    {"av", {"antivirus"}},
    {"csrf", {"cross site request forgery"}},
    {"cvss", {"common vulnerability scoring system"}},
    {"ddos", {"distributed denial of service"}},
    {"devops", {"development operations", "dev ops", "development and operations"}},
    {"dlp", {"data loss prevention", "data leakage protection"}},
    {"dmz", {"demilitarized zone"}},
    {"dns", {"domain name system"}},
    {"dos", {"denial of service"}},
    {"dpi", {"deep packet inspection"}},
    {"fim", {"file integrity monitoring"}},
    {"gdpr", {"general data protection regulation"}},
    {"hipaa", {"health insurance portability and accountability act"}},
    {"iam", {"identity and access management"}},
    {"ids", {"intrusion detection system"}},
    {"iot", {"internet of things"}},
    {"ips", {"intrusion prevention system"}},
    {"mfa", {"multi factor authentication"}},
    {"mssp", {"managed security service provider"}},
    {"nids", {"network intrusion detection system"}},
    {"nist", {"national institute of standards and technology"}},
    {"pci", {"payment card industry"}},
    {"pii", {"personally identifiable information"}},
    {"pki", {"public key infrastructure"}},
    {"rbac", {"role based access control"}},
    {"sast", {"static application security testing"}},
    {"sdlc", {"software development life cycle"}},
    {"siem", {"security information and event management"}},
    {"soc", {"security operations center"}},
    {"sql", {"structured query language"}},
    {"ssh", {"secure shell", "secure shell protocol"}},
    {"ssl", {"secure sockets layer"}},
    {"tls", {"transport layer security"}},
    {"vpn", {"virtual private network"}},
    {"waf", {"web application firewall"}},
    {"xss", {"cross site scripting"}}
};

std::string TextProcessor::normalize(const std::string& text) {
    std::string result;
    result.reserve(text.length());
    
    for (char c : text) {
        if (std::isalnum(c) || c == ' ' || c == '-') {
            result += std::tolower(c);
        }
    }
    return result;
}

bool TextProcessor::endsWith(const std::string& word, const std::string& suffix) {
    if (word.length() < suffix.length()) return false;
    return word.compare(word.length() - suffix.length(), suffix.length(), suffix) == 0;
}

std::string TextProcessor::stem(const std::string& word) {
    if (word.length() < 4) return word;
    
    std::string stemmed = word;
    
    // Handle special cases first
    if (endsWith(stemmed, "ies") && stemmed.length() > 4) {
        return stemmed.substr(0, stemmed.length() - 3) + "y";
    }
    
    // Try removing common suffixes
    for (const auto& suffix : COMMON_SUFFIXES) {
        if (endsWith(stemmed, suffix) && stemmed.length() > suffix.length() + 3) {
            return stemmed.substr(0, stemmed.length() - suffix.length());
        }
    }
    
    // Handle plural forms
    if (endsWith(stemmed, "s") && !endsWith(stemmed, "ss") && stemmed.length() > 3) {
        return stemmed.substr(0, stemmed.length() - 1);
    }
    
    return stemmed;
}

std::vector<std::string> TextProcessor::splitCamelCase(const std::string& word) {
    std::vector<std::string> result;
    if (word.empty()) return result;
    
    // std::cout << "DEBUG splitCamelCase: Processing word: '" << word << "'" << std::endl;
    
    // First, insert spaces before capital letters and numbers
    std::string spaced;
    spaced += word[0];
    
    for (size_t i = 1; i < word.length(); ++i) {
        char current = word[i];
        char prev = word[i-1];
        
        // Add space before:
        // 1. Capital letters (but not if previous was capital - handles acronyms like SSH)
        // 2. Numbers (but not if previous was a number)
        if ((std::isupper(current) && !std::isupper(prev)) ||
            (std::isdigit(current) && !std::isdigit(prev))) {
            spaced += ' ';
            // std::cout << "DEBUG splitCamelCase: Adding space before: '" << current << "'" << std::endl;
        }
        spaced += current;
    }
    
    // std::cout << "DEBUG splitCamelCase: After spacing: '" << spaced << "'" << std::endl;
    
    // Split by space and handle each part
    std::istringstream iss(spaced);
    std::string token;
    while (iss >> token) {
        // Check if token is an acronym (all uppercase)
        bool isAcronym = token.length() > 1 && 
                        std::all_of(token.begin(), token.end(), ::isupper);
        
        // std::cout << "DEBUG splitCamelCase: Found token: '" << token 
        //           << "', isAcronym: " << (isAcronym ? "true" : "false") << std::endl;
        
        // Convert to lowercase unless it's an acronym
        if (!isAcronym) {
            std::transform(token.begin(), token.end(), token.begin(), ::tolower);
            // std::cout << "DEBUG splitCamelCase: Lowercased to: '" << token << "'" << std::endl;
        }
        
        result.push_back(token);
    }
    
    // std::cout << "DEBUG splitCamelCase: Final tokens:" << std::endl;
    // for (const auto& t : result) {
    //     std::cout << "  - '" << t << "'" << std::endl;
    // }
    
    return result;
}

std::vector<std::string> TextProcessor::tokenize(const std::string& text) {
    std::vector<std::string> tokens;
    // std::cout << "DEBUG tokenize: Input text: '" << text << "'" << std::endl;
    
    // First split by whitespace while preserving case
    std::istringstream rawIss(text);
    std::string token;
    
    while (rawIss >> token) {
        if (!token.empty()) {
            // std::cout << "DEBUG tokenize: Processing token: '" << token << "'" << std::endl;
            
            // Check if the token might be camelCase
            bool hasCamelCase = false;
            bool hasLower = false;
            bool hasUpper = false;
            
            for (char c : token) {
                if (std::islower(c)) hasLower = true;
                if (std::isupper(c)) hasUpper = true;
                if (hasLower && hasUpper) {
                    hasCamelCase = true;
                    break;
                }
            }
            
            // std::cout << "DEBUG tokenize: Token analysis - hasLower: " << (hasLower ? "true" : "false")
            //           << ", hasUpper: " << (hasUpper ? "true" : "false")
            //           << ", hasCamelCase: " << (hasCamelCase ? "true" : "false") << std::endl;
            
            std::vector<std::string> parts;
            if (hasCamelCase || (token.find_first_of("0123456789") != std::string::npos)) {
                // std::cout << "DEBUG tokenize: Splitting camelCase word" << std::endl;
                parts = splitCamelCase(token);
            } else {
                // std::cout << "DEBUG tokenize: Adding token as-is" << std::endl;
                parts.push_back(token);
            }
            
            // Now normalize each part
            for (const auto& part : parts) {
                tokens.push_back(normalize(part));
            }
        }
    }
    
    // std::cout << "DEBUG tokenize: Final tokens:" << std::endl;
    // for (const auto& t : tokens) {
    //     std::cout << "  - '" << t << "'" << std::endl;
    // }
    
    return tokens;
}

std::vector<std::string> TextProcessor::generateNGrams(const std::string& text, size_t n) {
    std::vector<std::string> ngrams;
    auto tokens = tokenize(text);
    
    if (tokens.size() < n) {
        if (!tokens.empty()) {
            ngrams.push_back(text);
        }
        return ngrams;
    }
    
    for (size_t i = 0; i <= tokens.size() - n; ++i) {
        std::string ngram;
        for (size_t j = 0; j < n; ++j) {
            if (j > 0) ngram += " ";
            ngram += tokens[i + j];
        }
        ngrams.push_back(ngram);
    }
    
    return ngrams;
}

bool TextProcessor::isAbbreviation(const std::string& text) {
    std::string normalized = normalize(text);
    
    // Check if it's in our abbreviations map
    if (SECURITY_ABBREVIATIONS.find(normalized) != SECURITY_ABBREVIATIONS.end()) {
        return true;
    }
    
    // Check if it's all uppercase and at least 2 characters
    if (text.length() >= 2 && 
        std::all_of(text.begin(), text.end(), [](char c) { 
            return std::isupper(c) || std::isdigit(c); 
        })) {
        return true;
    }
    
    return false;
}

std::vector<std::string> TextProcessor::expandAbbreviations(const std::string& text) {
    std::vector<std::string> expansions;
    std::string normalized = normalize(text);
    
    // Check direct match in abbreviations
    auto it = SECURITY_ABBREVIATIONS.find(normalized);
    if (it != SECURITY_ABBREVIATIONS.end()) {
        expansions = it->second;
    }
    
    // Add the original text as well
    expansions.push_back(text);
    
    return expansions;
}

std::vector<std::string> TextProcessor::getAllWordCombinations(const std::string& phrase) {
    std::vector<std::string> combinations;
    auto tokens = tokenize(phrase);
    
    // Handle each token for abbreviations and keep original forms
    std::vector<std::string> expanded_tokens;
    for (const auto& token : tokens) {
        // Always add the original token (normalized)
        expanded_tokens.push_back(normalize(token));
        
        // Handle abbreviations
        if (isAbbreviation(token)) {
            auto expansions = expandAbbreviations(token);
            expanded_tokens.insert(expanded_tokens.end(), expansions.begin(), expansions.end());
        }
    }
    
    // Generate all possible n-grams from both original and expanded tokens
    for (size_t n = 1; n <= expanded_tokens.size(); ++n) {
        auto ngrams = generateNGrams(phrase, n);
        combinations.insert(combinations.end(), ngrams.begin(), ngrams.end());
    }
    
    // Add stemmed versions of tokens
    for (const auto& token : expanded_tokens) {
        combinations.push_back(stem(token));
    }
    
    // Remove duplicates
    std::sort(combinations.begin(), combinations.end());
    combinations.erase(std::unique(combinations.begin(), combinations.end()), combinations.end());
    
    return combinations;
} 
#include "Classifier.hpp"
#include "SecurityCategories.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <map>

void printClassification(const std::string& word, const SecurityClassification& result) {
    // Print header for this classification
    std::cout << "\nClassification for '" << word << "':\n";
    std::cout << std::string(60, '-') << "\n";
    
    // Primary classification result
    std::cout << "Term:       " << word << "\n";
    std::cout << "Category:   " << result.category << "\n";
    std::cout << "Confidence: " << std::fixed << std::setprecision(2) << (result.confidence * 100) << "%\n";
    std::cout << "Severity:   " << std::fixed << std::setprecision(2) << (result.severity * 100) << "%";
    if (result.severity >= 0.8f) std::cout << " (HIGH)";
    else if (result.severity >= 0.6f) std::cout << " (MEDIUM)";
    else std::cout << " (LOW)";
    std::cout << "\n\n";
    
    // Show top matching terms if available
    if (!result.similar_terms.empty()) {
        std::cout << "Top Similar Terms:\n";
        int count = 0;
        for (const auto& [term, score] : result.similar_terms) {
            std::cout << "  • " << std::left << std::setw(25) << term 
                      << " (similarity: " << std::fixed << std::setprecision(2) << (score * 100) << "%)\n";
            if (++count >= 3) break; // Show top 3 similar terms
        }
        std::cout << "\n";
    }
    
    // Show scores for all categories that had matches
    std::cout << "Category Breakdown:\n";
    for (const auto& score : result.all_scores) {
        if (score.confidence > 0.0f) {
            std::cout << "  " << std::left << std::setw(20) << score.category;
            std::cout << "Confidence: " << std::fixed << std::setprecision(2) 
                      << (score.confidence * 100) << "% ";
            std::cout << "Severity: " << std::fixed << std::setprecision(2) 
                      << (score.severity * 100) << "%";
            
            // Show top matching term for this category if available
            if (!score.matching_terms.empty()) {
                const auto& best_match = score.matching_terms.front();
                std::cout << " (Best match: '" << best_match.first << "')";
            }
            std::cout << "\n";
        }
    }
    std::cout << std::string(60, '-') << "\n";
}

int main() {
    Classifier classifier;
    
    if (!classifier.initialize("../models/security_model.bin")) {
        std::cerr << "Failed to load security model, trying to load full model...\n";
        if (!classifier.initialize("../models/wiki.en.bin")) {
            std::cerr << "Failed to initialize classifier" << std::endl;
            return 1;
        }
    }

    // Comprehensive test cases organized by category
    std::map<std::string, std::vector<std::string>> test_cases = {
        {"Vulnerability", {
            "vulnerability", "zero-day", "exploit",
            "security flaw", "system weakness", "critical bug"
        }},
        
        {"Attack", {
            "malware", "ransomware", "phishing attack",
            "social engineering", "ddos attack", "supply chain attack",
            "advanced persistent threat"
        }},
        
        {"Defense", {
            "firewall", "antivirus", "intrusion prevention",
            "security patch", "threat detection", "incident response",
            "defense in depth"
        }},
        
        {"Access Control", {
            "password", "two factor authentication", "access token",
            "privileged access", "role based access", "sudo permissions",
            "identity management"
        }},
        
        {"Network Security", {
            "network firewall", "vpn tunnel", "secure gateway",
            "network segmentation", "dmz setup", "packet filtering",
            "traffic analysis"
        }},
        
        {"Data Security", {
            "data encryption", "sensitive information", "data leakage",
            "confidential data", "data privacy", "data protection",
            "information security"
        }},
        
        {"Compliance", {
            "security compliance", "audit report", "security policy",
            "regulatory requirement", "security standard", "security framework",
            "security assessment"
        }},
        
        {"Incident Response", {
            "security incident", "breach notification", "incident handling",
            "forensic analysis", "threat hunting", "security alert",
            "incident containment"
        }},
        
        {"Infrastructure", {
            "cloud security", "container security", "server hardening",
            "infrastructure protection", "secure architecture", "endpoint security",
            "platform security"
        }}
    };

    std::cout << "\nComprehensive Security Classification Testing\n";
    std::cout << "==========================================\n";

    // Test each category
    for (const auto& [category, terms] : test_cases) {
        std::cout << "\nTesting " << category << " Category:\n";
        std::cout << "-----------------------------\n";
        
        for (const auto& term : terms) {
            auto classification = classifier.classifyWord(term);
            printClassification(term, classification);
        }
    }

    // Test some edge cases and compound terms
    std::cout << "\nTesting Edge Cases and Special Terms:\n";
    std::cout << "------------------------------------\n";
    std::vector<std::string> edge_cases = {
        "cybersecurity",              // Compound word
        "security operations center", // Multi-word term
        "DevSecOps",                 // Mixed case compound
        "CSRF attack",               // Abbreviation
        "red team blue team",        // Complex term
        "zero trust security",       // Modern concept
        "AI-powered security",       // Emerging tech
        "blockchain security",       // New technology
        "quantum cryptography",      // Advanced concept
        "security misconfiguration"  // Common issue
    };

    for (const auto& term : edge_cases) {
        auto classification = classifier.classifyWord(term);
        printClassification(term, classification);
    }

    std::cout << "\nNote: Classification threshold is set to " << SIMILARITY_THRESHOLD 
              << ". Adjust this value in Classifier.hpp to modify sensitivity.\n";

    return 0;
} 
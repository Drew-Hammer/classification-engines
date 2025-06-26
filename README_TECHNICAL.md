# Security and Exposure Classification System - Technical Documentation

## Architecture Overview
The system consists of two main classifiers:
1. Security Term Classifier - Identifies security-related terms and their severity
2. Exposure Classifier - Identifies potential exposure risks and their severity

Both classifiers use word embeddings and semantic similarity to classify input strings into predefined categories.

## Core Components

### 1. Base Classifier Class
The main engine that handles:
- Word vector loading and management
- Phrase tokenization and vector computation
- Similarity calculations
- Multi-category classification

### 2. Security Classifier
Inherits from base classifier and specializes in security classification:
```cpp
struct SecurityClassification {
    std::string category;
    float confidence;
    float severity;
    std::vector<CategoryScore> all_scores;
    std::vector<std::pair<std::string, float>> similar_terms;
};
```

### 3. Exposure Classifier
Specializes in exposure risk classification:
```cpp
class ExposureClassifier {
    std::vector<std::pair<std::string, double>> classify(const std::string& text);
    double getCategorySeverity(const std::string& category) const;
};
```

### 4. Categories

#### Security Categories
Nine predefined security categories with severity levels:
```cpp
const std::map<std::string, float> SECURITY_SEVERITY = {
    {"Vulnerability", 0.9f},
    {"Attack", 0.85f},
    // ... other categories
};
```

#### Exposure Categories
Thirteen predefined exposure categories with severity levels:
```cpp
const std::map<std::string, double> CATEGORY_SEVERITY = {
    {"Internet Exposure", 0.95},
    {"Credential Exposure", 0.90},
    {"Sensitive Data Exposure", 0.90},
    {"Network Exposure", 0.80},
    {"API Exposure", 0.80},
    {"Cloud Resource Exposure", 0.75},
    {"Container Exposure", 0.75},
    {"Service Exposure", 0.70},
    {"Configuration Exposure", 0.65},
    {"Infrastructure Exposure", 0.60},
    {"Debug Exposure", 0.55},
    {"Internal Exposure", 0.45},
    {"Documentation Exposure", 0.35}
};
```

### 5. Text Processing
Common text processing utilities used by both classifiers:
- Word splitting and normalization
- N-gram generation for multi-word terms
- Abbreviation handling
- Case-insensitive matching

## Classification Process

### Security Classification
1. Input phrase is tokenized and normalized
2. System checks for exact matches in security keywords
3. If no exact match, performs similarity matching
4. Returns classification with confidence and severity scores

### Exposure Classification
1. Input phrase is tokenized and normalized
2. FastText model predicts exposure category
3. System looks up predefined severity for the category
4. Returns category and severity score

## File Structure
```
src/
├── Classifier.hpp/.cpp        - Base classifier implementation
├── SecurityClassifier.hpp     - Security classifier interface
├── ExposureClassifier.hpp/.cpp - Exposure classifier implementation
├── SecurityCategories.hpp     - Security category definitions
├── ExposureCategories.hpp    - Exposure category definitions
├── TextProcessor.hpp/.cpp     - Common text processing utilities
├── test_engine.cpp           - Security classifier tests
└── test_exposure_engine.cpp  - Exposure classifier tests
```

For usage instructions, see README_USAGE.md

## Model Requirements
The classifier expects a binary model file containing word vectors in the following format:
- Header: `<vocab_size> <vector_dimension>`
- Entries: `<word> <v1> <v2> ... <vn>`

Model Format Example:
```
100000 300
word 0.1 0.2 0.3 ... (300 dimensions)
security 0.4 0.5 0.6 ... (300 dimensions)
...
```

## Future Improvements
1. Dynamic category addition
   - Runtime category definition
   - Dynamic severity adjustment
   - Custom keyword addition

2. Contextual classification
   - Sentence-level analysis
   - Context-aware scoring
   - Phrase relationships

3. Multi-language support
   - Language detection
   - Cross-lingual embeddings
   - Localized categories

4. Automated severity adjustment
   - Learning from usage patterns
   - Temporal severity changes
   - Context-based severity

5. Real-time model updates
   - Incremental learning
   - Online model updates
   - Adaptive thresholds

## Performance Considerations
- Memory Usage: ~1GB for full model, ~100MB for subset
- Classification Time: <10ms per term (typical)
- Load Time: 1-2 seconds for subset model
- Accuracy: >90% for known terms

## Testing
To run tests with different types of inputs:
```bash
# Compile the test program
g++ -std=c++17 src/test_classifier.cpp src/Classifier.cpp src/TextProcessor.cpp -o test_classifier

# Test single words
./test_classifier "vulnerability"

# Test phrases
./test_classifier "zero trust security"

# Test abbreviations
./test_classifier "CSRF attack"

# Test unknown terms
./test_classifier "quantum blockchain"
```

## Limitations
1. Vocabulary Constraints
   - Limited to terms in training data
   - May miss very new security terms
   - Abbreviation handling is predefined

2. Classification Boundaries
   - Fixed category definitions
   - Static severity scores
   - Binary category membership

3. Performance Tradeoffs
   - Memory vs. accuracy
   - Speed vs. completeness
   - Precision vs. recall 

## Customizing Security Categories and Models

### Adding New Security Categories

1. Update SecurityCategories.hpp:
```cpp
// Add to CATEGORY_SEVERITY map
const std::map<std::string, float> CATEGORY_SEVERITY = {
    // ... existing categories ...
    {"New Category", 0.75f},  // Set appropriate severity
};

// Add to CATEGORY_KEYWORDS map
const std::map<std::string, std::vector<std::string>> CATEGORY_KEYWORDS = {
    // ... existing categories ...
    {"New Category", {
        "primary_term",
        "synonym1",
        "synonym2",
        "related_term1",
        "related_phrase with spaces",
        // Add 10-20 core terms minimum
    }},
};
```

2. Best Practices for Category Definition:
- Choose severity level based on security impact:
  * 0.80-1.00: Critical security concerns
  * 0.60-0.79: Important operational concerns
  * 0.40-0.59: Policy and compliance matters
- Include diverse keyword variations:
  * Common abbreviations (e.g., "2FA", "MFA")
  * Full terms (e.g., "two-factor authentication")
  * Industry-standard phrases
  * Common misspellings
- Test new categories with:
  * Exact matches
  * Similar terms
  * Edge cases
  * Cross-category interactions

### Extending the Model Wordset

1. Creating a Custom Security Model:
```bash
# Start with base FastText model
cp wiki.en.bin security_base.bin

# Create security terms file
cat > security_terms.txt << EOL
vulnerability:exploit,zero-day,security_flaw
malware:virus,trojan,ransomware
authentication:2fa,mfa,password
EOL

# Train custom vectors (requires FastText)
fasttext train -model security_base.bin -dict security_terms.txt
```

2. Subsetting the Model:
```cpp
// In your code
std::set<std::string> required_words;
for (const auto& [category, keywords] : CATEGORY_KEYWORDS) {
    required_words.insert(keywords.begin(), keywords.end());
}
classifier.initialize("full_model.bin", required_words);
classifier.saveSubset("security_subset.bin", required_words);
```

3. Model Enhancement Strategies:
- Domain-Specific Training:
  * Collect security documentation
  * Extract technical terms
  * Generate word embeddings
  * Merge with base model

- Synonym Expansion:
  * Use WordNet for synonyms
  * Include technical variants
  * Add common abbreviations
  * Consider domain jargon

### Advanced Category Customization

1. Dynamic Category Loading:
```cpp
struct CategoryDefinition {
    std::string name;
    float severity;
    std::vector<std::string> keywords;
    bool is_enabled;
};

class CategoryManager {
public:
    void loadFromFile(const std::string& path);
    void addCategory(const CategoryDefinition& def);
    void updateSeverity(const std::string& category, float severity);
    void toggleCategory(const std::string& category, bool enabled);
};
```

2. Category Definition File Format:
```json
{
  "categories": [
    {
      "name": "Zero Day",
      "severity": 0.95,
      "keywords": [
        "zero-day",
        "0-day",
        "zero day exploit",
        "unpatched vulnerability"
      ],
      "enabled": true
    }
  ]
}
```

3. Category Optimization Tips:
- Keyword Selection:
  * Use frequency analysis
  * Consider term specificity
  * Include contextual variants
  * Monitor false positives

- Severity Tuning:
  * Analyze real-world impact
  * Consider industry standards
  * Adjust based on context
  * Regular review and updates

### Model Performance Optimization

1. Vector Space Analysis:
```cpp
// Analyze term relationships
float analyzeTermRelation(const std::string& term1, 
                         const std::string& term2,
                         const std::string& category) {
    float direct_sim = getSimilarity(term1, term2);
    float cat_sim1 = getCategorySimilarity(term1, category);
    float cat_sim2 = getCategorySimilarity(term2, category);
    return (direct_sim + cat_sim1 + cat_sim2) / 3.0f;
}
```

2. Category Overlap Detection:
```cpp
// Check category distinctiveness
void analyzeCategoryOverlap() {
    for (const auto& cat1 : categories) {
        for (const auto& cat2 : categories) {
            if (cat1.name != cat2.name) {
                float overlap = calculateCategoryOverlap(cat1, cat2);
                if (overlap > 0.7f) {
                    std::cout << "High overlap between "
                              << cat1.name << " and " 
                              << cat2.name << "\n";
                }
            }
        }
    }
}
```

3. Performance Monitoring:
- Track key metrics:
  * Classification accuracy
  * False positive rates
  * Category distribution
  * Processing time
- Regular evaluation:
  * Cross-validation
  * Edge case testing
  * Category effectiveness
  * Model drift analysis

### Maintenance and Updates

1. Regular Category Review:
- Monthly:
  * Check for new security terms
  * Update severity scores
  * Review classification accuracy
  * Add emerging threats

- Quarterly:
  * Full category audit
  * Remove obsolete terms
  * Merge similar categories
  * Update documentation

2. Model Maintenance:
- Version Control:
  * Track model changes
  * Document updates
  * Maintain backups
  * Test migrations

- Quality Assurance:
  * Regression testing
  * Performance benchmarks
  * Accuracy metrics
  * User feedback

3. Best Practices:
- Documentation:
  * Keep change logs
  * Update examples
  * Document decisions
  * Maintain guidelines

- Testing:
  * Unit tests
  * Integration tests
  * Performance tests
  * User acceptance

### Troubleshooting Category Issues

1. Common Problems:
- Misclassification:
  * Check keyword overlap
  * Review severity scores
  * Analyze similar terms
  * Test edge cases

- Performance Issues:
  * Optimize vector operations
  * Reduce category size
  * Cache common results
  * Profile critical paths

2. Diagnostic Tools:
```cpp
// Category analysis tool
struct CategoryMetrics {
    size_t term_count;
    float avg_similarity;
    float distinctiveness;
    std::vector<std::string> overlapping_terms;
};

CategoryMetrics analyzeCategoryHealth(const std::string& category);
```

3. Resolution Steps:
- For poor accuracy:
  * Add more keywords
  * Adjust similarity threshold
  * Review category boundaries
  * Update model vectors

- For slow performance:
  * Optimize keyword count
  * Cache frequent terms
  * Subset model data
  * Profile and optimize

Remember to maintain a balance between comprehensiveness and performance when extending categories or the model wordset. Regular testing and validation are crucial after any modifications. 
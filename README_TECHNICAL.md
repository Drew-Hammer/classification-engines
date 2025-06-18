# Security Term Classifier - Technical Documentation

## Architecture Overview
The Security Term Classifier is a C++ application that uses word embeddings and semantic similarity to classify security-related terms into predefined categories. It employs a multi-stage classification process with exact matching and similarity-based matching.

## Core Components

### 1. Classifier Class
The main engine that handles:
- Word vector loading and management
- Phrase tokenization and vector computation
- Similarity calculations
- Multi-category classification

Key Data Structures:
```cpp
struct CategoryScore {
    std::string category;
    float confidence;
    float severity;
    std::vector<std::pair<std::string, float>> matching_terms;
};

struct SecurityClassification {
    std::string category;
    float confidence;
    float severity;
    std::vector<CategoryScore> all_scores;
    std::vector<std::pair<std::string, float>> similar_terms;
};
```

### 2. Security Categories
Nine predefined security categories with assigned severity levels:
```
Vulnerability       (90%) - Direct security weaknesses
Attack             (85%) - Active threats
Incident Response  (80%) - Critical response needed
Access Control     (75%) - Security controls
Network Security   (70%) - Network protections
Data Security      (70%) - Data protection
Defense            (65%) - Security measures
Infrastructure     (60%) - System-level concerns
Compliance         (50%) - Policy and regulation
```

Category Implementation:
```cpp
const std::map<std::string, float> CATEGORY_SEVERITY = {
    {"Vulnerability", 0.9f},
    {"Attack", 0.85f},
    // ... other categories
};

const std::map<std::string, std::vector<std::string>> CATEGORY_KEYWORDS = {
    {"Vulnerability", {"vulnerability", "zero-day", "exploit", ...}},
    {"Attack", {"malware", "ransomware", "phishing", ...}},
    // ... other categories
};
```

### 3. Text Processing
- Word splitting and normalization
- N-gram generation for multi-word terms
- Abbreviation handling
- Case-insensitive matching

Text Processing Features:
- Handles compound words (e.g., "cybersecurity")
- Processes multi-word phrases (e.g., "zero trust security")
- Recognizes common security abbreviations (e.g., "CSRF", "2FA")
- Supports hyphenated terms (e.g., "zero-day")

## Classification Process

### Phase 1: Exact Matching
1. Input phrase is tokenized and normalized
2. System checks for exact matches in category keywords
3. If found, assigns 100% confidence and category's predefined severity

Implementation Details:
```cpp
// Tokenization
std::vector<std::string> splitPhrase(const std::string& phrase);

// Vector computation
std::vector<float> getWordVector(const std::string& word);
std::vector<float> getPhraseVector(const std::string& phrase);

// Similarity calculation
float getSimilarity(const std::string& word1, const std::string& word2);
```

### Phase 2: Similarity Matching
If no exact match is found:
1. Computes word vectors for input phrase
2. Calculates cosine similarity with category keywords
3. Identifies matches above threshold (default: 0.45)
4. Assigns highest confidence score and corresponding severity

Similarity Calculation:
```cpp
float similarity = dotProduct / (norm1 * norm2);
if (similarity > threshold) {
    // Update category scores
    category_scores[category].confidence = max(
        category_scores[category].confidence,
        similarity
    );
}
```

### Scoring System
- Confidence Score (0-100%): How well the term matches category keywords
- Severity Score (0-100%): Predefined per category based on security impact
- Similar Terms: Top 3 most similar terms found during classification

Score Normalization:
- Confidence scores are normalized to [0,1] range
- Severity scores are predefined constants
- Similar terms are sorted by similarity score

## Implementation Details

### Vector Operations
- Uses cosine similarity for semantic matching
- Handles multi-word phrases through vector averaging
- Normalizes vectors for consistent comparison

Vector Math:
```cpp
// Cosine similarity calculation
float dotProduct = 0.0f;
float norm1 = 0.0f;
float norm2 = 0.0f;

for (size_t i = 0; i < dimension_; i++) {
    dotProduct += vec1[i] * vec2[i];
    norm1 += vec1[i] * vec1[i];
    norm2 += vec2[i] * vec2[i];
}

return dotProduct / (sqrt(norm1) * sqrt(norm2));
```

### Performance Optimizations
- Subset model loading for reduced memory usage
- Early exit on exact matches
- Efficient vector operations
- Smart phrase tokenization

Memory Management:
- Uses unordered_map for O(1) word vector lookups
- Preallocates vectors to avoid reallocations
- Employs move semantics for vector operations
- Uses references to avoid unnecessary copies

### Error Handling
- Graceful handling of unknown terms
- Fallback to similarity matching when exact match fails
- Proper memory management for large vector operations

Error Cases:
- Missing model file
- Invalid word vectors
- Unknown terms
- Memory allocation failures
- File I/O errors

## File Structure
```
src/
├── Classifier.hpp     - Main classifier interface
├── Classifier.cpp     - Core classification logic
├── SecurityCategories.hpp - Category definitions
├── TextProcessor.cpp  - Text handling utilities
└── test_classifier.cpp - Simple test interface
```

Key Dependencies:
- C++17 Standard Library
- FastText word embeddings
- Standard Template Library (STL)

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
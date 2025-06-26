# Security and Exposure Classification System - Usage Guide

## Using as a Library in Your Code

### Integration Steps
1. Copy these files to your project:
   ```
   src/classification_engine.cpp
   src/classification_engine.hpp
   src/Classifier.cpp
   src/Classifier.hpp
   src/TextProcessor.cpp
   src/TextProcessor.hpp
   src/SecurityCategories.hpp
   src/ExposureCategories.hpp
   src/ExposureClassifier.cpp
   src/ExposureClassifier.hpp
   ```

2. Include the headers in your code:
   ```cpp
   #include "classification_engine.hpp"  // For security classification
   #include "ExposureClassifier.hpp"    // For exposure classification
   ```

3. Compile your code:
   ```bash
   # If compiling from the root directory:
   g++ -std=c++17 your_code.cpp src/*.cpp -o your_program

   # For testing:
   make test  # Builds and runs both security and exposure tests
   ```

### Usage Example
```cpp
#include "classification_engine.hpp"
#include "ExposureClassifier.hpp"
#include <iostream>

void checkSecurityAndExposure(const std::string& text) {
    // Security Classification
    setModelDirectory("models");  // Use relative or absolute path
    double security_severity = classifyText(text);
    
    if (security_severity >= 0.8) {
        std::cout << "HIGH security concern (" << (security_severity * 100) << "%)\n";
    } else if (security_severity >= 0.6) {
        std::cout << "MEDIUM security concern (" << (security_severity * 100) << "%)\n";
    } else if (security_severity > 0.0) {
        std::cout << "LOW security concern (" << (security_severity * 100) << "%)\n";
    }
    
    // Exposure Classification
    ExposureClassifier exposure_classifier;
    auto exposure_results = exposure_classifier.classify(text);
    
    for (const auto& [category, severity] : exposure_results) {
        if (severity >= 0.85) {
            std::cout << "CRITICAL exposure: " << category << " (" << (severity * 100) << "%)\n";
        } else if (severity >= 0.70) {
            std::cout << "HIGH exposure: " << category << " (" << (severity * 100) << "%)\n";
        } else if (severity >= 0.50) {
            std::cout << "MEDIUM exposure: " << category << " (" << (severity * 100) << "%)\n";
        } else {
            std::cout << "LOW exposure: " << category << " (" << (severity * 100) << "%)\n";
        }
    }
}
```

### Important Notes
- Security Classification:
  * Returns a double between -1.0 and 1.0
  * -1.0: Model loading failed
  * 0.0: Term not recognized
  * 0.0-1.0: Confidence/severity score
- Exposure Classification:
  * Returns vector of category-severity pairs
  * Each severity is between 0.0 and 1.0
  * Categories are predefined in ExposureCategories.hpp
- Features:
  * Handles camelCase words
  * Processes compound words
  * Case-insensitive matching
  * Thread-safe after initialization

### Model Requirements
- Security Classification:
  * Requires `security_model.bin` in models directory
  * Can be built using `build_custom_security_model.sh`
- Exposure Classification:
  * Requires exposure model built using `build_exposure_model.sh`

---

## Command-Line Testing

### Quick Start
```bash
# Build and test both classifiers
make test

# Test security classifier only
make test_security

# Test exposure classifier only
make test_exposure
```

### Example Classifications

#### Security Examples
- High Severity (≥80%):
  * "zero-day vulnerability"
  * "ransomware attack"
  * "SQL injection"
  
- Medium Severity (60-79%):
  * "firewall configuration"
  * "access control"
  * "network security"
  
- Low Severity (<60%):
  * "security policy"
  * "compliance report"

#### Exposure Examples
- Critical (≥85%):
  * "public internet access"
  * "exposed credentials"
  * "sensitive data leak"
  
- High (70-84%):
  * "open network port"
  * "public API endpoint"
  * "exposed container registry"
  
- Medium (50-69%):
  * "debug logs enabled"
  * "infrastructure details"
  
- Low (<50%):
  * "internal documentation"
  * "development notes"

### Understanding Results
Each classifier shows:
- Input text (with preprocessing)
- Classification confidence/severity
- Severity level
- Category details

### Troubleshooting
- If compilation fails:
  * Ensure all source files are present
  * Check C++17 compiler availability
  * Verify file paths
- If classification fails:
  * Check model files exist
  * Verify model file permissions
  * Run model build scripts if needed
- If getting unexpected results:
  * Try alternative phrasing
  * Check for typos
  * Use standard terminology 
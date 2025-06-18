# Security Term Classifier - Quick Usage Guide

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
   ```

2. Include the header in your code:
   ```cpp
   #include "classification_engine.hpp"
   ```

3. Compile your code with the classifier:
   ```bash
   # If compiling from the root directory:
   g++ -std=c++17 your_code.cpp src/classification_engine.cpp src/Classifier.cpp src/TextProcessor.cpp -o your_program

   # If you copied the files to your working directory:
   g++ -std=c++17 your_code.cpp classification_engine.cpp Classifier.cpp TextProcessor.cpp -o your_program
   ```

### Usage Example
```cpp
#include "classification_engine.hpp"
#include <iostream>

void checkSecuritySeverity(const std::string& text) {
    // Configure model directory (do this once at startup)
    // Option 1: Set a custom path
    setModelDirectory("/path/to/your/models");
    // Option 2: Use default "models" directory in current path
    setModelDirectory("models");
    
    // Classify text
    double severity = classifyText(text);
    
    if (severity >= 0.8) {
        std::cout << "HIGH security concern (" << (severity * 100) << "%)\n";
        // Handle high-severity case
    } else if (severity >= 0.6) {
        std::cout << "MEDIUM security concern (" << (severity * 100) << "%)\n";
        // Handle medium-severity case
    } else {
        std::cout << "LOW security concern (" << (severity * 100) << "%)\n";
        // Handle low-severity case
    }
}
```

### Important Notes
- The function `classifyText()` returns a double between 0.0 and 1.0
- Severity levels:
  * HIGH: ≥ 0.8 (80%)
  * MEDIUM: 0.6-0.79 (60-79%)
  * LOW: < 0.6 (below 60%)
- Model Path Configuration:
  * Use `setModelDirectory()` to set the path to your model files
  * Default is "models" in the current directory if not set
  * Path can be relative or absolute
  * No trailing slash needed (e.g., "models" not "models/")
- The classifier is initialized only once (uses static initialization)
- Handles camelCase and compound words automatically
- Thread-safe for classification but not for initialization

### Model Requirements
- Requires either `security_model.bin` or `wiki.en.bin` in your models directory
- Will attempt to load security-specific model first, then fall back to full model
- Returns -1.0 if no model can be loaded

### Model Configuration
You can configure where the model files are located in two ways:

1. Set the model directory globally (do this once at startup):
   ```cpp
   setModelDirectory("path/to/models");  // Use relative or absolute path
   double severity = classifyText("your text here");
   ```

2. Or specify the model directory per classification call:
   ```cpp
   double severity = classifyText("your text here", "path/to/models");
   ```

Note: The model directory should contain either `security_model.bin` or `wiki.en.bin`.

---

## Command-Line Usage

## Quick Start
1. Compile the classifier:
```bash
g++ -std=c++17 test_classifier.cpp Classifier.cpp TextProcessor.cpp -o test_classifier
```

2. Run the classifier with a security term or phrase:
```bash
./test_classifier "your security term here"
```

## Example Usage
```bash
# Test a high-severity term
./test_classifier "zero-day vulnerability"     # HIGH severity (90%)
./test_classifier "ransomware attack"         # HIGH severity (85%)
./test_classifier "data breach"               # HIGH severity (80%)

# Test a medium-severity term
./test_classifier "firewall"                  # MEDIUM severity (70%)
./test_classifier "access control"            # MEDIUM severity (75%)
./test_classifier "data encryption"           # MEDIUM severity (70%)

# Test a low-severity term
./test_classifier "security standard"         # LOW severity (50%)
./test_classifier "compliance policy"         # LOW severity (50%)
./test_classifier "audit report"              # LOW severity (50%)
```

## Understanding Results
The classifier will show:
- Category: The security category the term belongs to
- Confidence: How confident the classification is (0-100%)
- Severity: How severe the security term is (LOW/MEDIUM/HIGH)
- Similar Terms: Other related security terms (if found)

## Severity Levels
- HIGH (≥80%): Critical security concerns (vulnerabilities, attacks)
- MEDIUM (60-79%): Important but not critical (firewalls, access control)
- LOW (<60%): Policy and compliance related terms

## Tips
- Use quotes around multi-word phrases
- Try different variations of terms (e.g., "malware" vs "malicious software")
- The classifier handles common security abbreviations (e.g., "DDoS", "2FA")
- Terms can match multiple categories with different severities
- Unknown terms will return "Unknown" category with 0% confidence

## Common Categories
1. Vulnerability - Security weaknesses and exploits
2. Attack - Active threats and malicious activities
3. Defense - Protection mechanisms and controls
4. Access Control - Authentication and authorization
5. Network Security - Network-related protections
6. Data Security - Data protection and privacy
7. Compliance - Standards and regulations
8. Incident Response - Security incident handling
9. Infrastructure - System and platform security

## Troubleshooting
- If compilation fails, ensure all source files are in the same directory
- If model loading fails, check that the model file exists in ../models/
- For unknown terms, try using more common security terminology
- Multi-word phrases work best when they're standard security terms 
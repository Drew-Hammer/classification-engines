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

   g++ -std=c++17 test_engine.cpp src/classification_engine.cpp src/Classifier.cpp src/TextProcessor.cpp -o test_engine

   # If you copied the files to your working directory:
   g++ -std=c++17 your_code.cpp classification_engine.cpp Classifier.cpp TextProcessor.cpp -o your_program
   ```

### Usage Example
```cpp
#include "classification_engine.hpp"
#include <iostream>

void checkSecuritySeverity(const std::string& text) {
    // Set the model directory (do this once at startup)
    setModelDirectory("models");  // Use relative or absolute path
    
    // Classify text
    double severity = classifyText(text);
    
    if (severity >= 0.8) {
        std::cout << "HIGH security concern (" << (severity * 100) << "%)\n";
    } else if (severity >= 0.6) {
        std::cout << "MEDIUM security concern (" << (severity * 100) << "%)\n";
    } else if (severity > 0.0) {
        std::cout << "LOW security concern (" << (severity * 100) << "%)\n";
    } else {
        std::cout << "Classification failed or unknown term\n";
    }
}
```

### Important Notes
- The function `classifyText()` returns a double between -1.0 and 1.0
  * -1.0: Model loading failed or error occurred
  * 0.0: Term not recognized or very low confidence
  * 0.0-1.0: Confidence/severity score
- Model Path Configuration:
  * Use `setModelDirectory()` to set the path to your model files
  * Path can be relative or absolute
  * No trailing slash needed (e.g., "models" not "models/")
- Features:
  * Handles camelCase words automatically (e.g., "hasSsh" → "has ssh")
  * Processes compound words
  * Case-insensitive matching
  * Thread-safe for classification (after initialization)

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

## Command-Line Testing

### Quick Start
1. Compile the test program:
```bash
g++ -std=c++17 src/test_engine.cpp src/classification_engine.cpp src/Classifier.cpp src/TextProcessor.cpp -o test_engine
```

2. Run the test program:
```bash
./test_engine
```

The test program includes various test cases to demonstrate the classifier's capabilities.

### Example Classifications
- High Severity Terms (≥80%):
  * "zero-day vulnerability"
  * "ransomware attack"
  * "SQL injection"
  * "malware detected"
  
- Medium Severity Terms (60-79%):
  * "firewall configuration"
  * "access control"
  * "network security"
  * "password expired"
  
- Low Severity Terms (<60%):
  * "security policy"
  * "compliance report"
  * "documentation update"

### Understanding Results
The classifier shows:
- Input text (with any preprocessing applied)
- Classification confidence (0-100%)
- Severity level (HIGH/MEDIUM/LOW)
- Similar terms found (if any)

### Tips
- Use quotes around multi-word phrases
- The classifier handles:
  * CamelCase words (e.g., "hasSsh")
  * Common abbreviations (e.g., "2FA", "CSRF")
  * Compound words
  * Case variations
- Unknown terms return a score of 0.0
- Model loading failures return -1.0

### Common Categories
1. Vulnerability (90% base severity)
2. Attack (85% base severity)
3. Incident Response (80% base severity)
4. Access Control (75% base severity)
5. Network Security (70% base severity)
6. Data Security (70% base severity)
7. Defense (65% base severity)
8. Infrastructure (60% base severity)
9. Compliance (50% base severity)

### Troubleshooting
- If compilation fails:
  * Ensure all source files are present
  * Check C++17 compiler availability
  * Verify file paths in compilation command
- If classification returns -1.0:
  * Check model file exists in specified directory
  * Verify model file permissions
  * Ensure model file is not corrupted
- If classification returns 0.0:
  * Try alternative phrasing
  * Check for typos
  * Use more common security terminology 
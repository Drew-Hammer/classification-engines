# Security Term Classifier - Quick Usage Guide

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
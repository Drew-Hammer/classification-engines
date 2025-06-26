# EXPOSURE Classifier

A specialized classifier for identifying and scoring exposure risks in text descriptions. The classifier analyzes text for various types of exposure risks, including API exposure, credential exposure, network exposure, and more.

## Quick Start

```bash
# Build the classifier
make clean && make

# Run with a test phrase
./exposure_engine "Public API endpoint exposing user credentials"
```

## Categories and Severity

The classifier identifies several types of exposure risks:

### Critical (0.85-0.95)
- Internet Exposure (0.95) - Direct exposure to internet/public
- Credential Exposure (0.90) - Exposed passwords, keys, tokens
- Sensitive Data Exposure (0.90) - PII, financial data exposed
- Network Exposure (0.80) - Network level exposure
- API Exposure (0.80) - Exposed APIs and endpoints

### High (0.70-0.84)
- Cloud Resource Exposure (0.75) - Exposed cloud resources
- Container Exposure (0.75) - Container-related exposures
- Service Exposure (0.70) - Exposed internal services

### Medium (0.50-0.69)
- Configuration Exposure (0.65) - Exposed configs and settings
- Infrastructure Exposure (0.60) - Exposed infrastructure details
- Debug Exposure (0.55) - Debug/trace information exposure

### Low (0.30-0.49)
- Internal Exposure (0.45) - Internal system exposure
- Documentation Exposure (0.35) - Exposed internal documentation

## Output Format

The classifier provides detailed output including:
- Primary exposure category
- Confidence score (0-100%)
- Severity score (0-100%)
- Severity level (LOW/MEDIUM/HIGH)
- Top 3 similar terms with similarity scores
- Overall exposure engine score

Example output:
```
Exposure Classification Results for 'Public API endpoint exposing user credentials':
------------------------------------------------------------
Category:   API Exposure
Confidence: 85.23%
Severity:   80.00% (HIGH)

Similar Terms:
  • api_endpoint (similarity: 92.15%)
  • exposed_api (similarity: 88.73%)
  • public_api (similarity: 85.44%)

Exposure Engine Score: 0.823
```

## Usage in Code

The classifier can be used programmatically:

```cpp
#include "exposure_engine.hpp"

// Classify text and get exposure score (0.0 to 1.0)
double score = classifyExposure("Public API endpoint exposing credentials");

// Enable debug mode for detailed category scores
setExposureDebugMode(true);

// Set custom model directory if needed
setExposureModelDirectory("path/to/models");
```

## Model Files

The classifier requires the following model file in the `models` directory:
- `exposure_model.vec` - Pre-trained word vectors for exposure classification

## Building from Source

Requirements:
- C++17 compiler
- Make

Build steps:
```bash
cd EXPOSURE
make clean
make
``` 
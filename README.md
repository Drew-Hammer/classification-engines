# FastText-based Security and Exposure Classifier

This project implements a fast and efficient classification system that uses FastText vector embeddings to classify input strings based on two aspects:
1. Security Classification - Identifies security-related terms and their severity
2. Exposure Classification - Identifies potential exposure risks and their severity

## Features

- Uses FastText for generating vector embeddings
- Dual classification system:
  - Security classification for identifying security concerns
  - Exposure classification for identifying data/system exposure risks
- Local classification with pre-computed reference embeddings
- Configurable similarity threshold
- Support for top-k similar matches
- Fast cosine similarity comparison
- C++17 implementation for high performance
- Comprehensive severity scoring for both security and exposure
- Extensive term categorization

## Prerequisites

- C++17 compatible compiler (g++)
- Git (for fetching FastText dependency)

## Building and Testing the Project

The project uses a Makefile for building and testing. Here are the available commands:

```bash
# Build and test both classifiers
make test

# Test security classifier only
make test_security

# Test exposure classifier only
make test_exposure

# Clean build artifacts
make clean
```

## Classification Categories

### Security Categories
The security classifier includes comprehensive security categories with severity scoring:
- CRITICAL (0.85-0.95): Immediate system compromise risks
- HIGH (0.75-0.84): Direct security threats
- SIGNIFICANT (0.65-0.74): Major security components
- MEDIUM (0.55-0.64): Important security concerns

### Exposure Categories
The exposure classifier includes categories for identifying exposure risks:
- CRITICAL (0.85-0.95): Direct exposure to internet/public
  - Internet Exposure (0.95)
  - Credential Exposure (0.90)
  - Sensitive Data Exposure (0.90)
- HIGH (0.70-0.84): Significant exposure surface
  - Network Exposure (0.80)
  - API Exposure (0.80)
  - Cloud Resource Exposure (0.75)
  - Container Exposure (0.75)
  - Service Exposure (0.70)
- MEDIUM (0.50-0.69): Limited exposure
  - Configuration Exposure (0.65)
  - Infrastructure Exposure (0.60)
  - Debug Exposure (0.55)
- LOW (0.30-0.49): Minimal exposure
  - Internal Exposure (0.45)
  - Documentation Exposure (0.35)

Each category includes extensive keyword matching and context-aware classification.

## Version Control Notes

### Excluded Files and Directories
The following are not included in version control:

1. Model Files
- All model binary files (*.bin)
- Vector files (*.vec)
- Quantized models (*.ftz)
- Custom models (*.model)
- The entire `models/` directory

2. FastText Related
- The entire `fastText/` directory
- Wiki model files (wiki.*)
- Common Crawl files (cc.*)
- Any crawl-related data (crawl.*)

### Required Setup After Cloning

1. Model Setup
```bash
# Create models directory
mkdir -p models

# Build the exposure model
./lib/scripts/build_exposure_model.sh

# Build the security model
./lib/scripts/build_custom_security_model.sh
```

2. Build and Test
```bash
# Build and test both classifiers
make test
```

For detailed technical documentation, see README_TECHNICAL.md
For usage instructions, see README_USAGE.md 
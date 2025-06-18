# FastText-based String Classifier

This project implements a fast and efficient classification system that uses FastText vector embeddings to classify input strings based on similarity to reference examples.

## Features

- Uses FastText for generating vector embeddings
- Local classification with pre-computed reference embeddings
- Configurable similarity threshold
- Support for top-k similar matches
- Fast cosine similarity comparison
- C++17 implementation for high performance

## Prerequisites

- C++17 compatible compiler
- Git (for fetching FastText dependency)

## Building the Project

```bash
# Compile the classifier
g++ -std=c++17 src/test_engine.cpp src/classification_engine.cpp src/Classifier.cpp src/TextProcessor.cpp -o test_engine
```

## Usage

Before using the classifier, you'll need a pre-trained FastText model. You can either:
1. Use an existing FastText model
2. Train your own model using FastText's training tools

### Running the Example

The example program demonstrates how to use the classifier with some sample classifications:

```bash
./test_engine
```

### Using in Your Own Code

```cpp
#include "Classifier.hpp"

// Initialize classifier
Classifier classifier;
classifier.initialize("path/to/model.bin");

// Add reference strings and their labels
classifier.addReference("example string", "example_label");

// Pre-compute embeddings (do this after adding all references)
classifier.computeReferenceEmbeddings();

// Classify a string
auto result = classifier.classify("input string");
std::cout << "Label: " << result.label 
          << ", Confidence: " << result.confidence << std::endl;

// Get top-k matches
auto topMatches = classifier.getTopKMatches("input string", 3);
```

## Performance Considerations

- Reference embeddings are pre-computed and cached for faster classification
- Uses efficient cosine similarity calculation
- Minimal memory allocations during classification
- Thread-safe classification (after initialization)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

# Security Term Classifier

A C++ application for classifying security-related terms and phrases with severity scoring.

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

3. Sensitive Data
- Configuration files with secrets
- Private credentials
- API keys
- Certificates and keys
- Environment files

4. Large Datasets
- Training data
- Test datasets
- Large JSON/CSV files
- Custom word lists

### Required Setup After Cloning

1. Model Setup
```bash
# Create models directory
mkdir -p models

# Download required model (example)
# Note: You'll need to obtain the appropriate model file
# from your organization's secure storage
cp /path/to/your/security_model.bin models/
```

2. Configuration
```bash
# Create local config (if needed)
cp config.example.json config.local.json
# Edit config.local.json with your settings
```

### Maintaining Clean Version Control

1. Before Committing:
- Check for sensitive data in code comments
- Verify no model files are staged
- Ensure configuration files are templates only
- Remove any test datasets

2. Adding New Files:
- Update .gitignore if adding new file types
- Document required files in README
- Provide example/template files when needed

3. Sharing Code:
- Share model download instructions separately
- Document any required credentials
- Provide data format examples without real data

For detailed technical documentation, see README_TECHNICAL.md
For usage instructions, see README_USAGE.md 
#pragma once

#include <string>
#include <vector>
#include <utility>
#include "ExposureCategories.hpp"
#include "exposure_engine.hpp"  // For ExposureConfig

namespace exposure {

class ExposureClassifier {
public:
    ExposureClassifier();
    ~ExposureClassifier();

    // Main classification function
    std::vector<std::pair<std::string, double>> classify(const std::string& text);

    // Get severity score for a category
    double getCategorySeverity(const std::string& category) const;

    // Process exposure scores from a JSON file
    bool processExposureScores(const std::string& inputPath, bool verbose = false, bool printResults = false);
    bool processExposureScores(const std::string& inputPath, const ExposureConfig& config, bool verbose = false, bool printResults = false);

private:
    // Internal helper functions
    void initializeModel();
    std::string preprocessText(const std::string& text);
    std::vector<std::string> tokenizeText(const std::string& text);
};

} // namespace exposure 
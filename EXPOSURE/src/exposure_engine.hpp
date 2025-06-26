#pragma once

#include <string>
#include <vector>
#include <utility>

namespace exposure {

// Configuration struct for exposure classification
struct ExposureConfig {
    double internet_weight = 0.95;
    double credential_weight = 0.90;
    double data_weight = 0.90;
    double network_weight = 0.80;
    double api_weight = 0.80;
    double cloud_weight = 0.75;
    double container_weight = 0.75;
    double service_weight = 0.70;
    double config_weight = 0.65;
    double infra_weight = 0.60;
    double debug_weight = 0.55;
    double internal_weight = 0.45;
    double doc_weight = 0.35;
};

// Main function to classify text and get exposure scores
std::vector<std::pair<std::string, double>> classifyExposure(const std::string& text);

// Batch classification function
std::vector<std::vector<std::pair<std::string, double>>> classifyExposureBatch(
    const std::vector<std::string>& texts);

// Process exposure scores from a JSON file
bool processExposureScores(const std::string& inputPath, bool verbose = false, bool printResults = false);
bool processExposureScores(const std::string& inputPath, const ExposureConfig& config, bool verbose = false, bool printResults = false);

} // namespace exposure 
#pragma once

#include <string>
#include <vector>

namespace exposure {

// Main function to classify text and get exposure scores
std::vector<std::pair<std::string, double>> classifyExposure(const std::string& text);

// Batch classification function
std::vector<std::vector<std::pair<std::string, double>>> classifyExposureBatch(
    const std::vector<std::string>& texts);

} // namespace exposure 
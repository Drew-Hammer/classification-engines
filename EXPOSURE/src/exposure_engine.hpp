#ifndef EXPOSURE_ENGINE_HPP
#define EXPOSURE_ENGINE_HPP

#include <string>

// Function to set model directory
void setExposureModelDirectory(const std::string& directory);

// Function to set debug mode
void setExposureDebugMode(bool debug);

// Function to classify text and return exposure score between 0 and 1
// If model_dir is empty, uses the directory set by setExposureModelDirectory or falls back to "../models"
double classifyExposure(const std::string& text, const std::string& model_dir = "");

#endif // EXPOSURE_ENGINE_HPP 
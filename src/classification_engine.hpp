#ifndef CLASSIFICATION_ENGINE_HPP
#define CLASSIFICATION_ENGINE_HPP

#include <string>

// Function to set model directory
void setModelDirectory(const std::string& directory);

// Function to set debug mode
void setDebugMode(bool debug);

// Function to classify text and return severity score between 0 and 1
// If model_dir is empty, uses the directory set by setModelDirectory or falls back to "../models"
double classifyText(const std::string& text, const std::string& model_dir = "");

#endif // CLASSIFICATION_ENGINE_HPP 
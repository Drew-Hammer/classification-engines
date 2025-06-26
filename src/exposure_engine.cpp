#include "exposure_engine.hpp"
#include "ExposureClassifier.hpp"
#include <memory>

namespace exposure {

namespace {
    std::unique_ptr<Classifier> classifier;
}

std::vector<std::pair<std::string, double>> classifyExposure(const std::string& text) {
    if (!classifier) {
        classifier = std::make_unique<Classifier>();
        classifier->init("models/exposure_model.bin");
    }
    return classifier->classify(text);
}

std::vector<std::vector<std::pair<std::string, double>>> classifyExposureBatch(
    const std::vector<std::string>& texts) {
    if (!classifier) {
        classifier = std::make_unique<Classifier>();
        classifier->init("models/exposure_model.bin");
    }
    return classifier->classifyBatch(texts);
}

} // namespace exposure 
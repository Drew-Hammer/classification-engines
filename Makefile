CXX = g++
CXXFLAGS = -std=c++17

# Security engine targets
SECURITY_TARGET = security_engine
SECURITY_SRCS = src/test_engine.cpp src/classification_engine.cpp src/Classifier.cpp src/TextProcessor.cpp

# Exposure engine targets
EXPOSURE_TARGET = exposure_engine
EXPOSURE_SRCS = src/test_exposure_engine.cpp src/exposure_engine.cpp src/ExposureClassifier.cpp src/TextProcessor.cpp

# Build all targets
all: clean $(SECURITY_TARGET) $(EXPOSURE_TARGET)

# Build security engine
$(SECURITY_TARGET): $(SECURITY_SRCS)
	$(CXX) $(CXXFLAGS) $(SECURITY_SRCS) -o $(SECURITY_TARGET)

# Build exposure engine
$(EXPOSURE_TARGET): $(EXPOSURE_SRCS)
	$(CXX) $(CXXFLAGS) $(EXPOSURE_SRCS) -o $(EXPOSURE_TARGET)

# Test targets
test_security: clean $(SECURITY_TARGET)
	./$(SECURITY_TARGET)

test_exposure: clean $(EXPOSURE_TARGET)
	./$(EXPOSURE_TARGET)

test: clean test_security test_exposure

# Clean targets
clean:
	rm -f $(SECURITY_TARGET) $(EXPOSURE_TARGET)
	rm -f *.o src/*.o
	rm -f *.gch src/*.gch
	rm -f *~ src/*~

.PHONY: all test test_security test_exposure clean 
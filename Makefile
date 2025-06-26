CXX = g++
CXXFLAGS = -std=c++17

# Security engine targets
SECURITY_TARGET = security_engine
SECURITY_SRCS = src/test_engine.cpp src/classification_engine.cpp src/Classifier.cpp src/TextProcessor.cpp

# Build all targets
all: clean $(SECURITY_TARGET)

# Build security engine
$(SECURITY_TARGET): $(SECURITY_SRCS)
	$(CXX) $(CXXFLAGS) $(SECURITY_SRCS) -o $(SECURITY_TARGET)

# Test targets
test: clean $(SECURITY_TARGET)
	./$(SECURITY_TARGET)

# Clean targets
clean:
	rm -f $(SECURITY_TARGET)
	rm -f *.o src/*.o
	rm -f *.gch src/*.gch
	rm -f *~ src/*~

.PHONY: all test clean 
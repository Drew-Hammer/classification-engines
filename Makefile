CXX = g++
CXXFLAGS = -std=c++17
TARGET = test_engine
SRCS = src/test_engine.cpp src/classification_engine.cpp src/Classifier.cpp src/TextProcessor.cpp

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: test clean 
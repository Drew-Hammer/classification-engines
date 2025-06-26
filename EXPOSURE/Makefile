CXX = g++
CXXFLAGS = -std=c++17 -I.

# Source files
SRCS = src/exposure_engine.cpp \
       src/ExposureClassifier.cpp \
       src/test_exposure_engine.cpp

# Object files
OBJS = $(SRCS:.cpp=.o)

# Target executable
TARGET = exposure_engine

# Default target
all: $(TARGET)

# Link the target executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

# Compile source files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Test target
test: $(TARGET)
	./$(TARGET)

# Clean target
clean:
	rm -f $(TARGET) $(OBJS)
	rm -f *.o src/*.o
	rm -f *.gch src/*.gch
	rm -f *~ src/*~

.PHONY: all test clean 
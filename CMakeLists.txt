cmake_minimum_required(VERSION 3.10)
project(FastTextClassifier)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find required packages
find_package(cpprestsdk REQUIRED)

# Add executable
add_executable(classifier_service
    src/main.cpp
    src/Classifier.cpp
)

# Link libraries
target_link_libraries(classifier_service
    PRIVATE
    cpprestsdk::cpprest
    pthread
)

# Include directories
target_include_directories(classifier_service
    PRIVATE
    ${CMAKE_SOURCE_DIR}/src
) 
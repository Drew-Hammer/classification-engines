# Add the executable
add_executable(classifier
    main.cpp
    Classifier.cpp
    SecurityMappings.hpp
)

# Add include directories for the classifier
target_include_directories(classifier PRIVATE
    ${CMAKE_SOURCE_DIR}/fastText/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link against FastText library
target_link_libraries(classifier PRIVATE
    fasttext_lib
)

# Create an example executable
add_executable(classifier_example
    main.cpp
)

# Add include directories for the executable
target_include_directories(classifier_example PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(classifier_example
    classifier
    fasttext_lib
) 
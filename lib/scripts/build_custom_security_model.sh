#!/bin/bash

# Create necessary directories
mkdir -p models
mkdir -p fastText

# Function to extract keywords from SecurityCategories.hpp
extract_keywords() {
    echo "Extracting security keywords..."
    # Create a temporary file to store keywords
    cat > extract_keywords.cpp << 'EOL'
#include "src/SecurityCategories.hpp"
#include <iostream>
int main() {
    for (const auto& [category, keywords] : security::CATEGORY_KEYWORDS) {
        std::cout << "Category: " << category << std::endl;
        for (const auto& keyword : keywords) {
            std::cout << keyword << std::endl;
            // Output word parts for compound words
            std::string word = keyword;
            std::string delimiter = " ";
            size_t pos = 0;
            while ((pos = word.find(delimiter)) != std::string::npos) {
                std::cout << word.substr(0, pos) << std::endl;
                word.erase(0, pos + delimiter.length());
            }
            std::cout << word << std::endl;
        }
    }
    return 0;
}
EOL
    
    # Compile and run the extractor
    g++ -std=c++17 extract_keywords.cpp -o extract_keywords
    ./extract_keywords > security_keywords.txt
    rm extract_keywords.cpp extract_keywords
}

# Download FastText if not already present
if [ ! -d "fastText/.git" ]; then
    echo "Cloning FastText repository..."
    git clone https://github.com/facebookresearch/fastText.git
    cd fastText
    make
    cd ..
fi

# Extract keywords from your SecurityCategories.hpp
extract_keywords

echo "Creating training data..."
# Create training data with expanded context
while IFS= read -r line; do
    if [[ "$line" == "Category: "* ]]; then
        current_category="${line#Category: }"
        current_category_lower=$(echo "$current_category" | tr '[:upper:]' '[:lower:]')
    else
        # Convert line to lowercase
        line_lower=$(echo "$line" | tr '[:upper:]' '[:lower:]')
        # Add the term with its category
        echo "__label__security $current_category_lower $line_lower" >> training_data.txt
        # Add term variations
        if [[ "$line_lower" == *" "* ]]; then
            # Add underscore version
            echo "__label__security $current_category_lower ${line_lower// /_}" >> training_data.txt
            # Add parts separately
            for word in $line_lower; do
                echo "__label__security $current_category_lower $word" >> training_data.txt
            done
        fi
    fi
done < security_keywords.txt

# Add some common English words for context
cat >> training_data.txt << EOL
__label__general the
__label__general is
__label__general at
__label__general on
__label__general in
__label__general to
__label__general and
__label__general or
__label__general with
__label__general from
__label__general by
__label__general for
EOL

echo "Training custom security model..."
cd fastText
./fasttext supervised -input ../training_data.txt -output ../models/security_model -dim 100 -epoch 25 -lr 0.1 -wordNgrams 2 -minCount 1

echo "Cleaning up..."
rm -f ../security_keywords.txt ../training_data.txt
mv ../models/security_model.bin ../models/security_model.bin.new
mv ../models/security_model.vec ../models/security_model.vec.new

echo "Done! Your new security model is now available at models/security_model.bin.new"
echo "The model includes all terms from your SecurityCategories.hpp file with improved context handling."
echo "To use the new model, rename it from security_model.bin.new to security_model.bin" 
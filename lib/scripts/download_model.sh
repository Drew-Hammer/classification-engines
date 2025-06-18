#!/bin/bash

# Create models directory if it doesn't exist
mkdir -p models

# Download the FastText English word vectors
echo "Downloading FastText English word vectors..."
wget https://dl.fbaipublicfiles.com/fasttext/vectors-wiki/wiki.en.vec -O models/wiki.en.vec

# Convert to binary format
echo "Converting to binary format..."
cd fastText
./fasttext print-word-vectors ../models/wiki.en.vec > ../models/wiki.en.bin

echo "Done! Model is now available at models/wiki.en.bin" 
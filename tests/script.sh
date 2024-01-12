#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Usage: $0 <string>"
    exit 1
fi


ARG="$1"

if [ "$ARG" == "all" ]; then
    python3 -m unittest 
elif [ "$ARG" == "core" ]; then
    python3 -m unittest test_core.py
elif [ "$ARG" == "detector" ]; then
    python3 -m unittest test_detector.py
elif [ "$ARG" == "analyzer" ]; then
    python3 -m unittest test_analyzer.py
else
    python3 -m unittest 
fi



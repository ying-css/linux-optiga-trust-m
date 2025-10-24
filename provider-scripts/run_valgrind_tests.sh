#!/bin/bash

# Iterate over subdirectories
for dir in */ ; do
    script="$dir/valgrind_test.sh"
    if [ -f "$script" ]; then
        echo "Running $dir"
        (cd "$dir" && bash "valgrind_test.sh")
    else
        echo "$script not found, skipping."
    fi
done

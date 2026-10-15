#!/usr/bin/env bash
set -e
gcc -O2 -Wall -o gitpp gitpp.c -lm
echo "Built ./gitpp"
echo "Test: ./gitpp /path/to/records.json --at task-c"

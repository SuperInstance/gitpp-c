#!/usr/bin/env bash
set -e
# gnu99, not c99: fmemopen is a GNU extension and the binary compiles and
# exits 0 under -std=c99 while emitting nothing at all.
gcc -std=gnu99 -O2 -Wall -o gitpp gitpp.c -lm
echo "Built ./gitpp"
echo "Test: make test   (suite + end-to-end checks on ./gitpp)"

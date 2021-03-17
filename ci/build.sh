#!/bin/bash

set -e
set -x

mkdir build
cd build

cmake -DCMAKE_BUILD_TYPE=Debug -DCOVERAGE=ON ..
cmake --build . --config Debug --parallel 3 --target coverage

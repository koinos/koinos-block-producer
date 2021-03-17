#!/bin/bash

set -e
set -x

mkdir build
cd build

cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build . --config Debug --parallel 3 --target coverage

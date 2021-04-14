#!/bin/bash

set -e
set -x

if [[ -z $BUILD_DOCKER ]]; then
   mkdir build
   cd build

   cmake -DCMAKE_BUILD_TYPE=Release ..
   cmake --build . --config Release --parallel 3
else
   cp -R ~/.ccache ./.ccache
   docker build . -t koinos-block-producer-ccache --target builder
   docker build . -t koinos-block-producer
   docker run -td --name ccache koinos-block-producer-ccache
   docker cp ccache:/koinos-block-producer/.ccache ~/
fi

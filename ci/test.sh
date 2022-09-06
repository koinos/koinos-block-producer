#!/bin/bash
set -e
set -x

if ! [[ -z $BUILD_DOCKER ]]; then
   eval "$(gimme 1.18.1)"
   source ~/.gimme/envs/go1.18.1.env

   TAG="$TRAVIS_BRANCH"
   if [ "$TAG" = "master" ]; then
      TAG="latest"
   fi

   export BLOCK_PRODUCER_TAG=$TAG

   git clone https://github.com/koinos/koinos-integration-tests.git

   cd koinos-integration-tests
   go get ./...
   #./run.sh
fi

#!/bin/bash
set -e
set -x

if ! [[ -z $BUILD_DOCKER ]]; then
   eval "$(gimme 1.15.4)"
   source ~/.gimme/envs/go1.15.4.env

   TAG="$TRAVIS_BRANCH"
   if [ "$TAG" = "master" ]; then
      TAG="latest"
   fi

   export BLOCK_PRODUCER_TAG=$TAG

   git clone -b extended-time https://github.com/koinos/koinos-integration-tests.git

   cd koinos-integration-tests
   go get ./...
   cd tests
   ./run.sh
fi

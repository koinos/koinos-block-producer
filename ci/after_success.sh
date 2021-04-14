#!/bin/bash

if ! [[ -z $BUILD_DOCKER ]]; then
   TAG="$TRAVIS_BRANCH"
   if [ "$TAG" = "master" ]; then
      TAG="latest"
   fi

   echo "$DOCKER_PASSWORD" | docker login -u $DOCKER_USERNAME --password-stdin
   docker tag koinos-block-producer koinos/koinos-block-producer:$TAG
   docker push koinos/koinos-block-producer:$TAG
fi

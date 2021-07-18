#!/bin/bash
set -e

if [ -n "$1" ] ; then
  GIT_SHORT=$1
else
  GIT_SHORT=$(scripts/git-image-tag.sh)
fi

# Update deployment
kubectl set image deployment/$IMAGE  $IMAGE=$REGISTRY/$IMAGE:$GIT_SHORT

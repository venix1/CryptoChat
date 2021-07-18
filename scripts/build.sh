#!/bin/bash
set -e

# requires REGISTERY and IMAGE variables
GIT_SHORT="$(scripts/git-image-tag.sh)"

echo "git version: $GIT_SHORT"

# Build Image
podman build --format=docker -f Prophet -t ${IMAGE}:latest -t ${IMAGE}:$GIT_SHORT .
podman push ${IMAGE}:latest docker://$REGISTRY/${IMAGE}:latest
podman push ${IMAGE}:$GIT_SHORT docker://$REGISTRY/${IMAGE}:$GIT_SHORT

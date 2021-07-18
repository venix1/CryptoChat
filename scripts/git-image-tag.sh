#!/bin/bash
set -e

GIT_SHORT="$(git rev-parse --short HEAD)"
GIT_SHORT="$GIT_SHORT$(git submodule foreach --quiet 'git rev-parse --short HEAD' | awk '{printf "-"$1}')"
if [ -n "$BUILD_NUMBER" ]; then
    GIT_SHORT="$BUILD_NUMBER.$GIT_SHORT"
fi

echo "$GIT_SHORT"


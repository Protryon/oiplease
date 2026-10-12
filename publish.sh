#!/bin/bash
set -ex
here=$(realpath $(dirname "$0"))
cd "$here"

if [ -z ${1+x} ] ; then
    echo "missing tag"
    exit 1
fi

export TAG=$1

docker buildx build --platform linux/amd64,linux/arm64 -t protryon/oiplease:$TAG -f ./Dockerfile --push .

echo "Uploaded image protryon/oiplease:$TAG"

#!/bin/bash

BASE_DIR=$(dirname $0)
cd $BASE_DIR/..

if [ $1 ]; then
    npm uninstall -g node-gyp
    npm install -g node-gyp@$1
    echo "build with node-gyp $1"
fi

rm -rf build
node-gyp configure
node-gyp build

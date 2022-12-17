#!/bin/sh
# for build in docker
mkdir /tor/b
cd /tor/b
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .

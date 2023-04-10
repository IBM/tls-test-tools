#!/usr/bin/env bash

touch .bash_history
docker run --rm -it \
    --entrypoint bash \
    -w /src \
    -v ${PWD}:/src \
    -v ${PWD}/.bash_history:/root/.bash_history \
    tls-test-tools-develop $@

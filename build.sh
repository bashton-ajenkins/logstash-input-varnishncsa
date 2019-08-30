#!/bin/bash
IMAGE_NAME=logstash-input-varnishncsa
docker run --rm -v "$PWD:/usr/src/app" -w "/usr/src/app" jruby:9.1 bundle install
docker build -t "$IMAGE_NAME" .
docker run --rm -v "$PWD:/usr/src/app" -w "/usr/src/app" "$IMAGE_NAME" gem build logstash-input-varnishncsa.gemspec
#!/bin/bash

docker run --detach --rm \
-p 8090:8080 \
--name keycloak \
keycloak-mdm:latest \
start-dev --import-realm --proxy-headers xforwarded

./wait-for-it.sh -t 0 localhost:8090
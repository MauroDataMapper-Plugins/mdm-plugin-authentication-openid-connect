#!/bin/bash

docker run --rm \
-p 8090:8080 \
--name keycloak \
keycloak-mdm:latest \
start-dev --import-realm --proxy-headers xforwarded
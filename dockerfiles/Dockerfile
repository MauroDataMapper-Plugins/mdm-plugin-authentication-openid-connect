FROM quay.io/keycloak/keycloak

COPY ./realms/test_realm.json /opt/keycloak/data/import/test_realm.json

ENV KEYCLOAK_ADMIN=admin \
    KEYCLOAK_ADMIN_PASSWORD=password \
    PROXY_ADDRESS_FORWARDING=true \ 
    KC_HOSTNAME_PATH=/keycloak
/*
 * Copyright 2020-2023 University of Oxford and NHS England
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.jwt

import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.security.Utils
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.token.OpenidConnectToken

import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.Verification
import groovy.util.logging.Slf4j

/**
 * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
 * @since 02/06/2021
 */
@Slf4j
class OpenidConnectIdTokenJwtVerifier extends OpenidConnectJwtVerifier {

    final String tokenSessionState
    final String lastKnownSessionState
    final Long maxAgeOfAuthentication
    final String expectedNonce
    final String sessionId

    OpenidConnectIdTokenJwtVerifier(OpenidConnectToken token, String lastKnownSessionState) {
        super(token.decodedIdToken, token.openidConnectProvider)
        this.tokenSessionState = token.sessionState
        this.lastKnownSessionState = lastKnownSessionState
        this.maxAgeOfAuthentication = openidConnectProvider.authorizationEndpointParameters.maxAge
        this.sessionId = token.sessionId
        this.expectedNonce = Utils.generateNonceUuid(sessionId)

    }

    @Override
    Verification buildVerification() {
        Verification verification = super.buildVerification()
            .withClaim('nonce', expectedNonce)

        if (tokenSessionState)
            verification.withClaim('session_state', tokenSessionState)

        if (maxAgeOfAuthentication != null) {
            log.debug('Adding auth_time verification')
            verification.withClaimPresence('auth_time')
        }
        verification
    }

    @SuppressWarnings('GroovyVariableNotAssigned')
    void verify() throws JWTVerificationException {
        // Initial plain jwt verification
        // 1,2,3,4,5,6,7,9,10,11
        super.verify()

        // 12 (acr) out of scope

        // 13
        if (maxAgeOfAuthentication) {
            Long authDateSeconds = decodedToken.getClaim('auth_time').asLong()
            Long issuedDateSeconds = decodedToken.getClaim('iat').asLong()

            Long ageOfAuthentication = issuedDateSeconds - authDateSeconds
            Date agedDate = new Date(decodedToken.getClaim('auth_time').asDate().getTime() + (maxAgeOfAuthentication * 1000))
            if (ageOfAuthentication > maxAgeOfAuthentication) throw new JWTVerificationException("Authentication code can't be used after ${agedDate}")
        }

        // Addtl
        if (tokenSessionState && tokenSessionState != lastKnownSessionState) throw new JWTVerificationException('Token session_state must match previous session_state')

    }

    String getDecodedTokenVerificationString() {
        StringBuilder sb = new StringBuilder(super.getDecodedTokenVerificationString())
            .append('\n  Nonce: T> ').append(decodedToken.getClaim('nonce').asString())
            .append('\n         E> ').append(expectedNonce)

        if (tokenSessionState) {
            sb.append('\n  Session State: T> ').append(decodedToken.getClaim('session_state'))
                .append('\n                 E> ').append(tokenSessionState)
                .append('\n  Session State(last known): T> ').append(tokenSessionState)
                .append('\n                             E> ').append(lastKnownSessionState)
        }

        if (maxAgeOfAuthentication != null) {
            sb.append('\n  Max Age: T> ').append(decodedToken.getClaim('auth_time'))
                .append('\n           E> ').append(maxAgeOfAuthentication != null)
        }
        sb.append('\n  Session: T> ').append('NOT STORED')
            .append('\n           E> ').append(sessionId)
            .toString()
    }
}

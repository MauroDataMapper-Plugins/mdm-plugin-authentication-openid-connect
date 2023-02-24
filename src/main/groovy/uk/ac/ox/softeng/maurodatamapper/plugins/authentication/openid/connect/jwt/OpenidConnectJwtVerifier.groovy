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

import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiBadRequestException
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider

import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkProvider
import com.auth0.jwk.UrlJwkProvider
import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import com.auth0.jwt.interfaces.Verification
import groovy.util.logging.Slf4j

import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

/**
 * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
 * @since 02/06/2021
 */
@Slf4j
class OpenidConnectJwtVerifier {

    private JWTVerifier jwtVerifier

    final DecodedJWT decodedToken
    final OpenidConnectProvider openidConnectProvider
    boolean initialised

    OpenidConnectJwtVerifier(DecodedJWT decodedToken, OpenidConnectProvider openidConnectProvider) {
        this.decodedToken = decodedToken
        this.openidConnectProvider = openidConnectProvider
        this.initialised = false
    }

    void initialise() {
        jwtVerifier = buildVerification().build()
        initialised = true
    }

    Verification buildVerification() {
        JwkProvider provider = new UrlJwkProvider(openidConnectProvider.discoveryDocument.jwksUri.toURL())
        Jwk jsonWebKey = provider.get(decodedToken.keyId)
        Algorithm algorithm = getJwkAlgorithm(jsonWebKey)

        Verification verification = JWT.require(algorithm)
            .withIssuer(openidConnectProvider.discoveryDocument.issuer)
            .withAudience(openidConnectProvider.clientId)
            .withClaimPresence('email')

        if (decodedToken.audience.size() > 1) {
            log.debug('Adding azp verification')
            verification.withClaim('azp', openidConnectProvider.clientId)
        }
        verification
    }

    @SuppressWarnings('GroovyVariableNotAssigned')
    void verify() throws JWTVerificationException {
        if (!initialised) initialise()
        log.trace('OIC token to be verified\n{}', decodedTokenVerificationString)
        jwtVerifier.verify(decodedToken)
    }

    Algorithm getJwkAlgorithm(Jwk jwk) {
        switch (jwk.algorithm) {
            case 'RS256':
                return Algorithm.RSA256((RSAPublicKey) jwk.publicKey, null)
            case 'RS384':
                return Algorithm.RSA384((RSAPublicKey) jwk.publicKey, null)
            case 'RS512':
                return Algorithm.RSA512((RSAPublicKey) jwk.publicKey, null)
            case 'ES256':
                return Algorithm.ECDSA256((ECPublicKey) jwk.publicKey, null)
            case 'ES384':
                return Algorithm.ECDSA384((ECPublicKey) jwk.publicKey, null)
            case 'ES512':
                return Algorithm.ECDSA512((ECPublicKey) jwk.publicKey, null)
        }
        // If no algorithm then its probably Microsoft not meeting the basic standards
        // Therefore perform some "fall backs", the default expectation for OIC JWT is is actually RS256
        if (jwk.type == 'RSA') {
            return Algorithm.RSA256((RSAPublicKey) jwk.publicKey, null)
        }
        // verification 8 fail here
        throw new ApiBadRequestException('OCASXX', "Unsupported JWK Algorithm [${jwk.algorithm}] and JWK type [${jwk.type}] used by provider [${openidConnectProvider.label}]")
    }

    String getDecodedTokenVerificationString() {
        StringBuilder sb = new StringBuilder('OIC Token')
            .append('\n  Algorithm: ').append(decodedToken.algorithm)
            .append('\n  Issuer: T> ').append(decodedToken.issuer)
            .append('\n          E> ').append(openidConnectProvider.discoveryDocument.issuer)
            .append('\n  Audience: T> ').append(decodedToken.audience)
            .append('\n            E> ').append(openidConnectProvider.clientId)
            .append('\n  Email(must exist): ').append(decodedToken.getClaim('email'))

        if (decodedToken.audience.size() > 1) {
            sb.append('\n  AZP(audience > 1): T> ').append(decodedToken.getClaim('azp'))
                .append('\n                     E> ').append(openidConnectProvider.clientId)
        }
        sb.toString()
    }
}

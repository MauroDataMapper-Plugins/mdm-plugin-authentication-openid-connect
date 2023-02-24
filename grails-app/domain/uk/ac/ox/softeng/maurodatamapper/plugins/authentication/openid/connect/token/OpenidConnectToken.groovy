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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.token

import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.traits.domain.MdmDomain

import com.auth0.jwt.JWT
import com.auth0.jwt.exceptions.JWTDecodeException
import com.auth0.jwt.interfaces.Claim
import com.auth0.jwt.interfaces.DecodedJWT
import grails.gorm.DetachedCriteria

class OpenidConnectToken implements MdmDomain {

    UUID id
    CatalogueUser catalogueUser
    String sessionId
    String idToken
    String accessToken
    String refreshToken
    Long expiresIn
    Long refreshExpiresIn
    String sessionState
    String scope
    Integer notBeforePolicy
    String tokenType
    OpenidConnectProvider openidConnectProvider
    JWT jwt = new JWT()

    static constraints = {
        sessionId blank: false, unique: 'catalogueUser'
        idToken blank: false
        accessToken blank: false
        refreshToken blank: false, nullable: true
        expiresIn min: 0L
        refreshExpiresIn nullable: true, min: 0L
        sessionState nullable: true
        notBeforePolicy nullable: true
        path nullable: true
    }

    static mapping = {
        idToken type: 'text'
        accessToken type: 'text'
        refreshToken type: 'text'
    }
    static transients = ['jwt']

    @Override
    String getDomainType() {
        'OpenidConnectToken'
    }

    @Override
    String getPathPrefix() {
        return null
    }

    @Override
    String getPathIdentifier() {
        return null
    }

    DecodedJWT getDecodedIdToken() {
        safeDecodeJwt(idToken)
    }

    DecodedJWT getDecodedRefreshToken() {
        safeDecodeJwt(refreshToken)
    }

    Claim getIdTokenClaim(String name) {
        getDecodedIdToken().getClaim(name)
    }

    Date getAccessTokenExpiry() {
        decodedIdToken.expiresAt
    }

    Date getRefreshTokenExpiry() {
        decodedRefreshToken?.expiresAt
    }

    private DecodedJWT safeDecodeJwt(String token) {
        if (!token) return null
        try {
            jwt.decodeJwt(token)
        } catch (JWTDecodeException ignored) {
            null
        }
    }

    static DetachedCriteria<OpenidConnectToken> byEmailAddress(String emailAddress) {
        new DetachedCriteria<OpenidConnectToken>(OpenidConnectToken).where {
            catalogueUser {
                eq('emailAddress', emailAddress)
            }
        }
    }


}

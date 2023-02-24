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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider

import uk.ac.ox.softeng.maurodatamapper.gorm.constraint.callable.CallableConstraints
import uk.ac.ox.softeng.maurodatamapper.gorm.constraint.callable.MdmDomainConstraints
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.details.DiscoveryDocument
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.parameters.AuthorizationEndpointParameters
import uk.ac.ox.softeng.maurodatamapper.traits.domain.MdmDomain

import grails.gorm.DetachedCriteria
import grails.rest.Resource
import io.micronaut.http.uri.UriBuilder

@Resource(readOnly = false, formats = ['json', 'xml'])
class OpenidConnectProvider implements MdmDomain {

    UUID id
    String label
    Boolean standardProvider

    String discoveryDocumentUrl

    String clientId
    String clientSecret

    AuthorizationEndpointParameters authorizationEndpointParameters
    DiscoveryDocument discoveryDocument
    String imageUrl

    static constraints = {
        CallableConstraints.call(MdmDomainConstraints, delegate)
        label unique: true, blank: false
        discoveryDocumentUrl blank: false, url: true, nullable: true, validator: {val, obj ->
            if (obj.standardProvider && !val) return ['default.null.message']
        }
        clientId blank: false
        clientSecret blank: false
        imageUrl url: true, blank: false, nullable: true
        path nullable: true
    }

    static mapping = {
        discoveryDocument cascade: 'all-delete-orphan'
        authorizationEndpointParameters cascade: 'all-delete-orphan'
    }

    OpenidConnectProvider() {
        authorizationEndpointParameters = new AuthorizationEndpointParameters()
    }

    @Override
    String getDomainType() {
        OpenidConnectProvider.simpleName
    }

    @Override
    String getPathPrefix() {
        null
    }

    @Override
    String getPathIdentifier() {
         null
    }

    def beforeValidate() {
        authorizationEndpointParameters?.openidConnectProvider = this
        authorizationEndpointParameters?.createdBy = this.createdBy
        discoveryDocument?.openidConnectProvider = this
        discoveryDocument?.createdBy = this.createdBy
    }

    Map<String, String> getAccessTokenRequestParameters(String code, String redirectUri, String sessionState) {
        [
            grant_type   : 'authorization_code',
            client_id    : clientId,
            code         : code,
            redirect_uri : redirectUri,
            client_secret: clientSecret,
            session_state: sessionState
        ]
    }

    Map<String, String> getAccessTokenRefreshRequestParameters(String refreshToken) {
        [
            grant_type   : 'refresh_token',
            client_id    : clientId,
            client_secret: clientSecret,
            refresh_token: refreshToken
        ]
    }

    String getFullAuthorizationEndpointUrl(String sessionId) {
        UriBuilder builder = UriBuilder.of(discoveryDocument.authorizationEndpoint)
        authorizationEndpointParameters.getAsMap(sessionId).each {k, v ->
            builder = builder.queryParam(k, v)
        }
        builder.build().toString()
    }

    static DetachedCriteria<OpenidConnectProvider> by() {
        new DetachedCriteria<OpenidConnectProvider>(OpenidConnectProvider)
    }
}
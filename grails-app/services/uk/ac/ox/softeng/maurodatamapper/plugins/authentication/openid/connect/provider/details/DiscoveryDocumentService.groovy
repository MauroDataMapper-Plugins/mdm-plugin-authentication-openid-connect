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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.details

import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiInternalException
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider

import grails.gorm.transactions.Transactional
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.http.uri.UriBuilder

@Transactional
class DiscoveryDocumentService {

    DiscoveryDocument loadDiscoveryDocumentForOpenidConnectProvider(OpenidConnectProvider openidConnectProvider) {
        if (!openidConnectProvider) throw new ApiInternalException('DDS02', 'Cannot retrieve discovery document for unknown provider')
        Map<String,Object> dataMap = loadDiscoveryDocumentMapFromUrl(openidConnectProvider.discoveryDocumentUrl)
        createDiscoveryDocument(dataMap)
    }

    Map<String, Object> loadDiscoveryDocumentMapFromUrl(String discoveryDocumentUrl) {
        loadDiscoveryDocumentMapFromUrl(UriBuilder.of(discoveryDocumentUrl).build().toURL())
    }

    Map<String, Object> loadDiscoveryDocumentMapFromUrl(URL discoveryDocumentUrl) {
        try {
            String baseUrl = "${discoveryDocumentUrl.protocol}://${discoveryDocumentUrl.host}"
            if (discoveryDocumentUrl.port != -1) baseUrl = "${baseUrl}:${discoveryDocumentUrl.port}"
            HttpClient client = HttpClient.create(baseUrl.toURL())
            HttpRequest request = HttpRequest.GET(discoveryDocumentUrl.path).contentType(MediaType.APPLICATION_JSON_TYPE).accept(MediaType.APPLICATION_JSON_TYPE)
            client.toBlocking().exchange(request, Argument.mapOf(String, Object)).body()
        } catch (HttpClientResponseException responseException) {
            throw new ApiInternalException('DDS01', "Cannot retrieve discovery document from ${discoveryDocumentUrl.toString()}", responseException)
        }
    }

    DiscoveryDocument createDiscoveryDocument(Map<String, Object> data) {
        DiscoveryDocument document = new DiscoveryDocument(data)
        document.authorizationEndpoint = data.authorization_endpoint
        document.tokenEndpoint = data.token_endpoint
        document.userinfoEndpoint = data.userinfo_endpoint
        document.endSessionEndpoint = data.end_session_endpoint ?:data.revocation_endpoint
        document.jwksUri = data.jwks_uri
        document
    }
}

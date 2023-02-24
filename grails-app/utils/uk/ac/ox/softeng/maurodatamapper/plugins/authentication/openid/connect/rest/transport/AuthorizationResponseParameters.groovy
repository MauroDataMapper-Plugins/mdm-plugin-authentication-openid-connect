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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.rest.transport

import uk.ac.ox.softeng.maurodatamapper.util.Utils

/**
 * @since 02/06/2021
 */
class AuthorizationResponseParameters {

    UUID openidConnectProviderId
    String sessionState
    String code
    String state
    String redirectUri

    AuthorizationResponseParameters(Map<String, Object> parameters) {
        openidConnectProviderId = Utils.toUuid(parameters.openidConnectProviderId)
        this.sessionState = parameters.sessionState ?: parameters.session_state
        this.redirectUri = parameters.redirectUri ?: parameters.redirect_uri
        // Codes come in URL to UI we need to make sure they're decoded for the post request
        this.code = parameters.code ? URLDecoder.decode(parameters.code as String, 'UTF-8') : null
        this.state = parameters.state
    }

    String toString(String sessionId, String oicProvider) {
        new StringBuilder('Authorization Response Parameters for ')
            .append(sessionId)
            .append('\n  OIC: ').append(oicProvider)
            .append('\n  Session State: ').append(sessionState)
            .append('\n  State: ').append(state)
            .append('\n  Code: ').append(code)
        .toString()
    }
}

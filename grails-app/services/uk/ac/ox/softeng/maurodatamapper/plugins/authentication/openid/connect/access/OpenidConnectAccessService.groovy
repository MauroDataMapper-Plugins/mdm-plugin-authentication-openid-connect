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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.access


import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProviderService
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.token.OpenidConnectToken
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.token.OpenidConnectTokenService

import groovy.util.logging.Slf4j

import java.time.Duration
import javax.servlet.http.HttpSession
import javax.servlet.http.HttpSessionEvent
import javax.servlet.http.HttpSessionListener

/**
 * @since 15/06/2021
 */
@Slf4j
class OpenidConnectAccessService implements HttpSessionListener{

    static final String ACCESS_EXPIRY_SESSION_ATTRIBUTE_NAME='openidAccessExpiry'
    static final String REFRESH_EXPIRY_SESSION_ATTRIBUTE_NAME='openidRefreshExpiry'
    static final String OPEN_ID_AUTHENTICATION_SESSION_ATTRIBUTE_NAME='openidAuthentication'

    OpenidConnectTokenService openidConnectTokenService
    OpenidConnectProviderService openidConnectProviderService

    /**
     * Destruction of the session should result in us revoking any access tokens and removing them from the backend
     * @param se
     */
    @Override
    void sessionDestroyed(HttpSessionEvent se) {
        if(se.session.getAttribute(OPEN_ID_AUTHENTICATION_SESSION_ATTRIBUTE_NAME)) {
            // We should try to revoke the token to the provider which will also remove the token stored in the backedn
            openidConnectTokenService.revokeTokenBySessionId(se.session.id)
            log.debug('Openid Connect session {} destroyed', se.session.id)
        }
    }

    void storeTokenDataIntoHttpSession(OpenidConnectToken openidConnectToken, HttpSession session, Duration sessionTimeoutOverride = null){
        session.setAttribute(OPEN_ID_AUTHENTICATION_SESSION_ATTRIBUTE_NAME, true)
        session.setAttribute(ACCESS_EXPIRY_SESSION_ATTRIBUTE_NAME, openidConnectToken.getAccessTokenExpiry())
        session.setAttribute(REFRESH_EXPIRY_SESSION_ATTRIBUTE_NAME, openidConnectToken.getRefreshTokenExpiry())
        if(sessionTimeoutOverride != null) session.setMaxInactiveInterval(sessionTimeoutOverride.seconds.toInteger())
    }
}

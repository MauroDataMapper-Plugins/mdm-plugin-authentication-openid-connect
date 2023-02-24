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

import uk.ac.ox.softeng.maurodatamapper.core.session.SessionService
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.token.OpenidConnectToken
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.token.OpenidConnectTokenService
import uk.ac.ox.softeng.maurodatamapper.security.UserSecurityPolicyManagerInterceptor
import uk.ac.ox.softeng.maurodatamapper.security.authentication.AuthenticatingService
import uk.ac.ox.softeng.maurodatamapper.security.interceptor.SecurityPolicyManagerInterceptor

import groovy.util.logging.Slf4j

import static uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.access.OpenidConnectAccessService.ACCESS_EXPIRY_SESSION_ATTRIBUTE_NAME
import static uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.access.OpenidConnectAccessService.OPEN_ID_AUTHENTICATION_SESSION_ATTRIBUTE_NAME
import static uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.access.OpenidConnectAccessService.REFRESH_EXPIRY_SESSION_ATTRIBUTE_NAME

@Slf4j
class OpenidConnectAccessInterceptor implements SecurityPolicyManagerInterceptor {

    OpenidConnectTokenService openidConnectTokenService
    OpenidConnectAccessService openidConnectAccessService
    AuthenticatingService authenticatingService

    SessionService sessionService

    OpenidConnectAccessInterceptor() {
        match(uri: '/**/api/**/')
        // We want to check access before we try to load the usersecuritypolicy manager
        order = UserSecurityPolicyManagerInterceptor.ORDER - 5000
    }

    boolean before() {

        if (sessionService.isAuthenticatedSession(session.id)) {

            if (session.getAttribute(OPEN_ID_AUTHENTICATION_SESSION_ATTRIBUTE_NAME)) {
                log.debug('User has authenticated using openid, need to check access is still valid')
                // Not expired then dont need to do anything else
                if (!hasTokenExpired(session.getAttribute(ACCESS_EXPIRY_SESSION_ATTRIBUTE_NAME) as Date)) return true

                log.debug('Access token has expired')
                if (!session.getAttribute(REFRESH_EXPIRY_SESSION_ATTRIBUTE_NAME)) {
                    log.warn('Token expired, no refresh token available, user logged out')
                    return logUserOut()
                }

                log.debug('Refresh token available')
                if (hasTokenExpired(session.getAttribute(REFRESH_EXPIRY_SESSION_ATTRIBUTE_NAME) as Date)) {
                    log.warn('Token expired & refresh token expired, user logged out')
                    return logUserOut()
                }

                log.debug('Refresh token still valid')
                OpenidConnectToken refreshedOpenidToken = openidConnectTokenService.refreshTokenBySessionId(session.id)
                if (!refreshedOpenidToken) {
                    log.warn('Token expired & refresh token failed, user logged out')
                    return logUserOut()
                }

                openidConnectAccessService.storeTokenDataIntoHttpSession(refreshedOpenidToken, session)
                log.debug('Token has been refreshed and saved')
            }
        }
        true
    }

    private boolean logUserOut() {
        // Logging out the user will destroy their session which will call our session hook
        authenticatingService.registerUserAsLoggedOut(session)
        unauthorised('Session has been invalidated')
    }

    private static boolean hasTokenExpired(Date expiresAt){
        Date now = new Date()
        now = new Date((now.getTime() / 1000).toLong() * 1000) // truncate millis
        return now.after(expiresAt)
    }
}

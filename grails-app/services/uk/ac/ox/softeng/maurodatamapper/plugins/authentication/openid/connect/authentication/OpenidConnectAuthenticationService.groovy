/*
 * Copyright 2020-2022 University of Oxford and Health and Social Care Information Centre, also known as NHS Digital
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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.authentication

import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiInvalidModelException
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.access.OpenidConnectAccessService
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProviderService
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.rest.transport.AuthorizationResponseParameters
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.token.OpenidConnectToken
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.token.OpenidConnectTokenService
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.BootStrap
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUserService
import uk.ac.ox.softeng.maurodatamapper.security.authentication.AuthenticationSchemeService
import uk.ac.ox.softeng.maurodatamapper.core.admin.ApiProperty
import uk.ac.ox.softeng.maurodatamapper.core.admin.ApiPropertyService

import grails.core.GrailsApplication
import grails.gorm.transactions.Transactional
import groovy.util.logging.Slf4j

import java.time.Duration
import java.time.format.DateTimeParseException
import javax.servlet.http.HttpSession

/**
 * https://auth0.com/docs/flows/authorization-code-flow
 * https://www.keycloak.org/docs/latest/securing_apps/index.html#endpoints
 *
 */
@Transactional
@Slf4j
class OpenidConnectAuthenticationService implements AuthenticationSchemeService {

    OpenidConnectProviderService openidConnectProviderService
    OpenidConnectTokenService openidConnectTokenService
    OpenidConnectAccessService openidConnectAccessService

    CatalogueUserService catalogueUserService
    GrailsApplication grailsApplication

    ApiPropertyService apiPropertyService
    Map<String, ApiProperty> apiPropertyMap = getRequiredApiProperties()

    @Override
    String getName() {
        'openIdConnect'
    }

    @Override
    String getDisplayName() {
        'OpenId Connect Authentication Service'
    }

    @Override
    int getOrder() {
        0
    }

    @Transactional
    CatalogueUser authenticateAndObtainUser(Map<String, Object> authenticationInformation) {
        log.info('Attempt to authenticate system using Openid Connect')

        AuthorizationResponseParameters authorizationResponseParameters = new AuthorizationResponseParameters(authenticationInformation)
        HttpSession session = authenticationInformation.session as HttpSession

        OpenidConnectProvider openidConnectProvider = openidConnectProviderService.get(authorizationResponseParameters.openidConnectProviderId)

        if (!openidConnectProvider) {
            log.warn('Attempt to authenticate using unknown OAUTH Provider')
            return null
        }

        log.trace('Requesting token\n{}', authorizationResponseParameters.toString(session.id, openidConnectProvider.label))
        Map<String, Object> responseBody = openidConnectProviderService.loadTokenFromOpenidConnectProvider(openidConnectProvider,
                                                                                                           openidConnectProvider.getAccessTokenRequestParameters(
                                                                                                               authorizationResponseParameters.code,
                                                                                                               authorizationResponseParameters.redirectUri,
                                                                                                               authorizationResponseParameters.sessionState)
        )

        if (!responseBody) {
            log.warn("Failed to get access token from Openid Connect Provider [${openidConnectProvider.label}]")
            return null
        }

        if (responseBody.error) {
            log.warn("Failed to get access token from Openid Connect Provider [${openidConnectProvider.label}] because [${responseBody.error_description}]")
            return null
        }

        OpenidConnectToken token = openidConnectTokenService.createToken(openidConnectProvider, responseBody, session.id)

        log.debug('Verifying token for session {}', session.id)
        if (!openidConnectTokenService.verifyIdToken(token, authorizationResponseParameters.sessionState)) {
            return null
        }

        String emailAddress = token.getIdTokenClaim('email').asString()

        CatalogueUser user = catalogueUserService.findByEmailAddress(emailAddress)

        Map<String, ApiProperty> apiPropertyMap = getRequiredApiProperties()
        if (!user && !apiPropertyMap.autoRegisterUserProperty?.value?.toBoolean()) {
            // User not found, so return null
            return null
        }

        if (!user) {
            log.info('Creating new user {}', emailAddress)

            Map<String, Object> userInfoBody = openidConnectProviderService.loadUserInfoFromOpenidConnectProvider(openidConnectProvider, token.accessToken)

            URL issuerUrl = openidConnectProvider.discoveryDocument.issuer.toURL()
            user = catalogueUserService.createNewUser(emailAddress: emailAddress,
                                                      password: null,
                                                      firstName: userInfoBody.given_name ?: 'Unknown',
                                                      lastName: userInfoBody.family_name ?: 'Unknown',
                                                      createdBy: "openidConnectAuthentication@${issuerUrl.authority}",
                                                      pending: false,
                                                      creationMethod: 'OpenID-Connect')

            if (!user.validate()) throw new ApiInvalidModelException('OCAS02:', 'Invalid user creation', user.errors)
            user.save(flush: true, validate: false)
            user.addCreatedEdit(user)
        }

        token.createdBy = user.emailAddress
        token.catalogueUser = user

        Duration timeoutOverride = null
        try {
            timeoutOverride = Duration.parse("pt${grailsApplication.config.maurodatamapper.openidConnect.session.timeout}")
            log.debug('Overriding standard session timeout to {}', timeoutOverride)
        } catch (DateTimeParseException ignored) {}

        openidConnectTokenService.validateAndSave(token)
        openidConnectAccessService.storeTokenDataIntoHttpSession(token,session , timeoutOverride)

        user
    }

    Map<String, ApiProperty> getRequiredApiProperties() {
        List<ApiProperty> apiPropertyList = ApiProperty.findAllByCategory(BootStrap.OPEN_ID_PROPERTY_CATEGORY)
        [
            autoRegisterUserProperty: apiPropertyList.find {it.key == BootStrap.AUTO_REGISTER_USER_KEY}
        ]
    }
}

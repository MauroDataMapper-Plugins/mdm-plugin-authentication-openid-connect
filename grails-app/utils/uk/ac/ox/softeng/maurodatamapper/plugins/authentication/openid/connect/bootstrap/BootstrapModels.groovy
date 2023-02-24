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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.bootstrap

import uk.ac.ox.softeng.maurodatamapper.core.bootstrap.StandardEmailAddress
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.details.DiscoveryDocumentService

import groovy.util.logging.Slf4j
import org.springframework.context.MessageSource

import static uk.ac.ox.softeng.maurodatamapper.util.GormUtils.checkAndSave

/**
 * @since 27/05/2021
 */
@Slf4j
class BootstrapModels {

    public static final String GOOGLE_OPENID_CONNECT_PROVIDER_NAME = 'Google'
    public static final String MICROSOFT_OPENID_CONNECT_PROVIDER_NAME = 'Microsoft'
    public static final String KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME = 'Keycloak'

    static OpenidConnectProvider buildAndSaveGoogleProvider(MessageSource messageSource, Map openidConnectConfig, DiscoveryDocumentService discoveryDocumentService) {
        log.info('Adding [{}] Open-id Connect Provider', GOOGLE_OPENID_CONNECT_PROVIDER_NAME)
        OpenidConnectProvider openidConnectProvider = new OpenidConnectProvider(
            label: GOOGLE_OPENID_CONNECT_PROVIDER_NAME,
            createdBy: StandardEmailAddress.ADMIN,
            standardProvider: true,
            discoveryDocumentUrl: "https://accounts.google.com/.well-known/openid-configuration",
            clientId: openidConnectConfig.clientId,
            clientSecret: openidConnectConfig.clientSecret,
            imageUrl: 'https://upload.wikimedia.org/wikipedia/commons/5/53/Google_%22G%22_Logo.svg'
            )
        openidConnectProvider.discoveryDocument = discoveryDocumentService.loadDiscoveryDocumentForOpenidConnectProvider(openidConnectProvider)
        checkAndSave(messageSource, openidConnectProvider)
        openidConnectProvider
    }

    static OpenidConnectProvider buildAndSaveMicrosoftProvider(MessageSource messageSource, Map openidConnectConfig, DiscoveryDocumentService discoveryDocumentService) {
        log.info('Adding [{}] Open-id Connect Provider', MICROSOFT_OPENID_CONNECT_PROVIDER_NAME)
        OpenidConnectProvider openidConnectProvider = new OpenidConnectProvider(
            label: MICROSOFT_OPENID_CONNECT_PROVIDER_NAME,
            createdBy: StandardEmailAddress.ADMIN,
            standardProvider:true,
            discoveryDocumentUrl: "https://login.microsoftonline.com/${openidConnectConfig.accountId}/v2.0/.well-known/openid-configuration",
            clientId: openidConnectConfig.clientId,
            clientSecret: openidConnectConfig.clientSecret,
            imageUrl: 'https://upload.wikimedia.org/wikipedia/commons/9/98/Microsoft_logo.jpg'
            )
        openidConnectProvider.discoveryDocument = discoveryDocumentService.loadDiscoveryDocumentForOpenidConnectProvider(openidConnectProvider)
        openidConnectProvider.discoveryDocument.issuer = openidConnectProvider.discoveryDocument.issuer.replace('{tenantid}', openidConnectConfig.tenantId)

        checkAndSave(messageSource, openidConnectProvider)
        openidConnectProvider
    }

    static OpenidConnectProvider buildAndSaveKeycloakProvider(MessageSource messageSource, Map openidConnectConfig, DiscoveryDocumentService discoveryDocumentService) {
        log.info('Adding [{}] Open-id Connect Provider', KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME)
        OpenidConnectProvider openidConnectProvider = new OpenidConnectProvider(
            label: KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME,
            createdBy: StandardEmailAddress.ADMIN,
            standardProvider: true,
            discoveryDocumentUrl: "${openidConnectConfig.baseUrl}/realms/${openidConnectConfig.realm}/.well-known/openid-configuration",
            clientId: openidConnectConfig.clientId,
            clientSecret: openidConnectConfig.clientSecret,
            imageUrl: 'https://upload.wikimedia.org/wikipedia/commons/2/29/Keycloak_Logo.png'
            )
        openidConnectProvider.discoveryDocument = discoveryDocumentService.loadDiscoveryDocumentForOpenidConnectProvider(openidConnectProvider)
        checkAndSave(messageSource, openidConnectProvider)
        openidConnectProvider
    }
}

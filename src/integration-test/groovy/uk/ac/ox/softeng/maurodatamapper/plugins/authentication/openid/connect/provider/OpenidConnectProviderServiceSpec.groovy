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

import uk.ac.ox.softeng.maurodatamapper.core.bootstrap.StandardEmailAddress
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.bootstrap.BootstrapModels
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.details.DiscoveryDocument
import uk.ac.ox.softeng.maurodatamapper.test.integration.BaseIntegrationSpec

import grails.gorm.transactions.Rollback
import grails.testing.mixin.integration.Integration
import groovy.util.logging.Slf4j

import static uk.ac.ox.softeng.maurodatamapper.util.GormUtils.checkAndSave

@Rollback
@Integration
@Slf4j
class OpenidConnectProviderServiceSpec extends BaseIntegrationSpec {

    OpenidConnectProviderService openidConnectProviderService


    @Override
    void setupDomainData() {
        OpenidConnectProvider openidConnectProvider = new OpenidConnectProvider(
            label: 'integration test provider',
            createdBy: StandardEmailAddress.ADMIN,
            standardProvider: false,
            clientId: 'test',
            clientSecret: 'test secret',
            discoveryDocument: new DiscoveryDocument(
                issuer: 'https://test.com',
                authorizationEndpoint: 'https://test.com/authorise',
                tokenEndpoint: 'https://test.com/token',
                userinfoEndpoint: 'https://test.com/userinfo',
                jwksUri: 'https://test.com/certs'
            )
        )
        checkAndSave(messageSource, openidConnectProvider)
        id = openidConnectProvider.id
    }

    void "test get"() {
        given:
        setupData()

        expect:
        openidConnectProviderService.get(id) != null
    }

    void "test list"() {
        given:
        setupData()

        when:
        List<OpenidConnectProvider> openidConnectProviderList = openidConnectProviderService.list(max: 2, orderBy: 'label')

        then:
        openidConnectProviderList.size() == 2

        when:
        def ocp1 = openidConnectProviderList[0]
        def ocp2 = openidConnectProviderList[1]

        then:
        ocp1.label == BootstrapModels.GOOGLE_OPENID_CONNECT_PROVIDER_NAME

        and:
        ocp2.label == BootstrapModels.KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME

    }

    void "test count"() {
        given:
        setupData()

        expect:
        openidConnectProviderService.count() == 3
    }

    void "test delete"() {
        given:
        setupData()

        expect:
        openidConnectProviderService.count() == 3
        OpenidConnectProvider ocp = openidConnectProviderService.get(id)

        when:
        openidConnectProviderService.delete(ocp)

        then:
        OpenidConnectProvider.count() == 2
    }

}

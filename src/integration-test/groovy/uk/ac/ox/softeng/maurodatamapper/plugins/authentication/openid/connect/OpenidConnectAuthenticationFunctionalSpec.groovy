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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect

import uk.ac.ox.softeng.maurodatamapper.core.bootstrap.StandardEmailAddress
import uk.ac.ox.softeng.maurodatamapper.core.container.Folder
import uk.ac.ox.softeng.maurodatamapper.core.session.SessionService
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.access.OpenidConnectAccessService
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.bootstrap.BootstrapModels
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProviderService
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.token.OpenidConnectToken
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUserService
import uk.ac.ox.softeng.maurodatamapper.test.functional.BaseFunctionalSpec

import grails.core.GrailsApplication
import grails.gorm.transactions.Transactional
import grails.testing.mixin.integration.Integration
import groovy.util.logging.Slf4j
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpResponse
import org.jsoup.Connection
import org.jsoup.Jsoup
import org.jsoup.nodes.Document
import org.jsoup.nodes.FormElement
import spock.lang.Ignore
import spock.lang.Shared

import java.time.Duration
import javax.servlet.ServletContext
import javax.servlet.http.HttpSession

import static io.micronaut.http.HttpStatus.NOT_FOUND
import static io.micronaut.http.HttpStatus.OK
import static io.micronaut.http.HttpStatus.UNAUTHORIZED

/**
 *
 * <pre>
 * Controller: authenticating
 * |  POST  | /api/admin/activeSessions  | Action: activeSessionsWithCredentials
 * |  *     | /api/authentication/logout | Action: logout
 * |  POST  | /api/authentication/login  | Action: login
 * </pre>
 * @see uk.ac.ox.softeng.maurodatamapper.security.authentication.AuthenticatingController
 */
@Slf4j
@Integration
class OpenidConnectAuthenticationFunctionalSpec extends BaseFunctionalSpec {

    CatalogueUserService catalogueUserService
    SessionService sessionService
    ServletContext servletContext
    GrailsApplication grailsApplication
    OpenidConnectProviderService openidConnectProviderService

    @Shared
    String sessionId

    @Shared
    byte[] nonce

    @Shared
    String urlEncodedNonce

    def setupSpec() {
        sessionId = 'cdb2fd10-1021-4758-abb9-c1e9e4eb0c19'
        //nonce = SecurityUtils.getHash(sessionId)
        nonce = [124, 70, 127, -33, 91, 53, -18, 47, -92, -30, -52, -5, 34, -64, -61, -97, 82, -97, 19, -99, -42, -39, -84, -43, 0, -32, -70, -70, 123, -1, 114, 106]
       //urlEncodedNonce = URLEncoder.encode(new String(nonce), Charset.defaultCharset())
        urlEncodedNonce = '%7CF%7F%EF%BF%BD%5B5%EF%BF%BD%2F%EF%BF%BD%EF%BF%BD%EF%BF%BD%EF%BF%BD%22%EF%BF%BD%C3%9FR%EF%BF%BD%13%EF%BF%BD%EF%BF%BD%D9%AC%EF%BF%BD%00%E0%BA%BA%7B%EF%BF%BDrj'
    }

    @Transactional
    void deleteUser(String id) {
        catalogueUserService.get(id).delete(flush: true)
    }

    def cleanup() {
        List<HttpSession> sessions = new ArrayList<>(servletContext.getAttribute(SessionService.CONTEXT_PROPERTY_NAME).values())
        log.warn('Destroying {} left over sessions', sessions.size())
        sessions.each {it.invalidate()}
    }

    @Transactional
    OpenidConnectProvider getKeycloakProvider() {
        OpenidConnectProvider provider = OpenidConnectProvider.findByLabel(BootstrapModels.KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME)
        provider.getFullAuthorizationEndpointUrl(sessionId)
        provider
    }

    @Transactional
    OpenidConnectProvider getGoogleProvider() {
        OpenidConnectProvider provider = OpenidConnectProvider.findByLabel(BootstrapModels.GOOGLE_OPENID_CONNECT_PROVIDER_NAME)
        provider.getFullAuthorizationEndpointUrl(sessionId)
        provider
    }

    @Transactional
    String getFolderId() {
        Folder.findByLabel('Functional Test Folder').id.toString()
    }

    @Transactional
    CatalogueUser getUser(String emailAddress) {
        CatalogueUser.findByEmailAddress(emailAddress)
    }

    @Transactional
    void updateRefreshTokenForUserToken(String emailAddress, Long expiresIn) {
        OpenidConnectToken token = OpenidConnectToken.byEmailAddress(emailAddress).get()
        token.refreshExpiresIn = expiresIn
        token.save(flush: true)
    }

    @Transactional
    void updateAccessTokenForUserToken(String emailAddress, Long expiresIn) {
        OpenidConnectToken token = OpenidConnectToken.byEmailAddress(emailAddress).get()
        token.expiresIn = expiresIn
        token.save(flush: true)
    }

    @Transactional
    void getToken(String sessionId) {
        OpenidConnectToken.findBySessionId(sessionId)
    }

    @Transactional
    void updateKeycloakProviderMaxAge(Long maxAge) {
        OpenidConnectProvider provider = OpenidConnectProvider.findByLabel(BootstrapModels.KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME)
        provider.authorizationEndpointParameters.maxAge = maxAge
        provider.save(flush: true)
    }

    @Transactional
    OpenidConnectProvider createAzureProvider(String ddUrl, String clientId, String clientSecret, String tenantId) {
        OpenidConnectProvider provider = new OpenidConnectProvider(label: 'Functional Test Azure',
                                                                   standardProvider: true,
                                                                   discoveryDocumentUrl: ddUrl,
                                                                   clientId: clientId,
                                                                   clientSecret: clientSecret,
                                                                   createdBy: StandardEmailAddress.FUNCTIONAL_TEST)
        openidConnectProviderService.loadDiscoveryDocumentIntoOpenidConnectProvider(provider)
        provider.discoveryDocument.issuer = provider.discoveryDocument.issuer.replace('{tenantid}', tenantId)
        provider.save(flush: true)
        provider.getFullAuthorizationEndpointUrl(sessionId)
        provider
    }

    @Override
    String getResourcePath() {
        'authentication'
    }

    void 'PUBLIC - test getting public endpoint of providers'() {
        when:
        GET('openidConnectProviders', STRING_ARG, true)

        then:
        verifyResponse(OK, jsonCapableResponse)
        log.info('{}', jsonCapableResponse.body())
    }

    void 'KEYCLOAK01 - test logging in with empty authentication code'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak()
        authorizeResponse.code = ''

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK02 - test logging in with random authentication code'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak()
        authorizeResponse.code = UUID.randomUUID().toString()

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK03 - test logging in with no authentication code'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak()
        authorizeResponse.remove('code')


        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK04 - test logging in with valid authentication code and invalid session_state'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak()
        authorizeResponse.sessionState = UUID.randomUUID().toString()

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK05 - test logging in with valid authentication code and invalid nonce'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak('mdm-admin', 'mdm-admin', UUID.randomUUID().toString())

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK06 - test logging in with valid authentication code and parameters with existing user'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak()

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(OK, response)

        when: 'grab the session created'
        HttpSession session = getSession(StandardEmailAddress.ADMIN)

        then: 'session timeout has been overridden to 24hrs which is the default for this plugin'
        session.maxInactiveInterval == Duration.ofHours(24).seconds
    }

    void 'KEYCLOAK07 - test logging in with valid authentication code and parameters with non-existent user'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak('keycloak-only', 'keycloak-only')

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(OK, response)

        when: 'check user has been created'
        CatalogueUser user = getUser('keycloak-only@maurodatamapper.com')

        then:
        user
        user.firstName == 'keycloak-only'
        user.lastName == 'User'
        user.createdBy == 'openidConnectAuthentication@jenkins.cs.ox.ac.uk'
    }

    void 'KEYCLOAK08 - test logging in with valid authentication code and altered max_age'() {
        given:
        updateKeycloakProviderMaxAge(1)
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak('mdm-admin', 'mdm-admin')

        when: 'in call made to login'
        sleep(2000)
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)

        cleanup:
        updateKeycloakProviderMaxAge(null)
    }

    void 'KEYCLOAK09 - test access inside timeout'() {

        when: 'not logged in'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'folder is not available'
        verifyResponse(NOT_FOUND, response)

        when: 'logged in'
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak('mdm-admin', 'mdm-admin')
        POST('login?scheme=openIdConnect', authorizeResponse)
        verifyResponse(OK, response)

        and: 'getting folder'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'folder available'
        verifyResponse(OK, response)
    }

    void 'KEYCLOAK10 - test access after timeout with no refresh token'() {

        when: 'not logged in'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'folder is not available'
        verifyResponse(NOT_FOUND, response)

        when: 'logged in'
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak('mdm-admin', 'mdm-admin')
        POST('login?scheme=openIdConnect', authorizeResponse)
        verifyResponse(OK, response)

        and: 'removing refresh token'
        updateRefreshTokenForUserToken('admin@maurodatamapper.com', 1)
        HttpSession session = getSession(StandardEmailAddress.ADMIN)
        session.removeAttribute(OpenidConnectAccessService.REFRESH_EXPIRY_SESSION_ATTRIBUTE_NAME)

        and: 'expiring access token'
        updateAccessTokenForUserToken('admin@maurodatamapper.com', 1)
        Date date = getExpiredTime()
        log.debug('Overriding expiry time to {} for session {}', date, session.id)
        session.setAttribute(OpenidConnectAccessService.ACCESS_EXPIRY_SESSION_ATTRIBUTE_NAME, date)

        and: 'getting folder'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'session timed out and unauthorised'
        verifyResponse(UNAUTHORIZED, response)

        when: 'getting folder'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'expected response for unlogged in user'
        verifyResponse(NOT_FOUND, response)
    }

    void 'KEYCLOAK11 - test access after timeout with expired refresh token'() {

        when: 'not logged in'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'folder is not available'
        verifyResponse(NOT_FOUND, response)

        when: 'logged in'
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak('mdm-admin', 'mdm-admin')
        POST('login?scheme=openIdConnect', authorizeResponse)
        verifyResponse(OK, response)

        and: 'expiring refresh token'
        // now
        updateRefreshTokenForUserToken('admin@maurodatamapper.com', 1)
        HttpSession session = getSession(StandardEmailAddress.ADMIN)
        session.setAttribute(OpenidConnectAccessService.REFRESH_EXPIRY_SESSION_ATTRIBUTE_NAME, getExpiredTime())

        and: 'expiring access token'
        updateAccessTokenForUserToken('admin@maurodatamapper.com', 1)
        session.setAttribute(OpenidConnectAccessService.ACCESS_EXPIRY_SESSION_ATTRIBUTE_NAME, getExpiredTime())

        and: 'getting folder'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'session timed out and unauthorised'
        verifyResponse(UNAUTHORIZED, response)

        when: 'getting folder'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'expected response for unlogged in user'
        verifyResponse(NOT_FOUND, response)
    }

    void 'KEYCLOAK12 - test access after timeout with refresh token'() {

        when: 'not logged in'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'folder is not available'
        verifyResponse(NOT_FOUND, response)

        when: 'logged in'
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak('mdm-admin', 'mdm-admin')
        POST('login?scheme=openIdConnect', authorizeResponse)
        verifyResponse(OK, response)

        and: 'expiring access token'
        HttpSession session = getSession(StandardEmailAddress.ADMIN)
        updateAccessTokenForUserToken('admin@maurodatamapper.com', 1)
        // now
        session.setAttribute(OpenidConnectAccessService.ACCESS_EXPIRY_SESSION_ATTRIBUTE_NAME, getExpiredTime())

        and: 'getting folder'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'session timed out and unauthorised'
        verifyResponse(OK, response)
    }

    void 'KEYCLOAK13 - test access after session invalidated'() {

        when: 'not logged in'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'folder is not available'
        verifyResponse(NOT_FOUND, response)

        when: 'logged in'
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak('mdm-admin', 'mdm-admin')
        POST('login?scheme=openIdConnect', authorizeResponse)
        verifyResponse(OK, response)

        and: 'timeout session'
        // Usually we have a session timeout of 24hrs which is not testable so we reduce the session timeout to 2 seconds which will result in the server destroying our
        // session for us
        HttpSession session = getSession(StandardEmailAddress.ADMIN)
        session.setMaxInactiveInterval(2)

        and: 'getting folder'
        sleep(3000)
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'session timed out folder is not available\''
        verifyResponse(NOT_FOUND, response)
    }

    void 'KEYCLOAK14 - test access after logout'() {

        when: 'not logged in'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'folder is not available'
        verifyResponse(NOT_FOUND, response)

        when: 'logged in'
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak('mdm-admin', 'mdm-admin')
        POST('login?scheme=openIdConnect', authorizeResponse)
        verifyResponse(OK, response)
        HttpSession session = getSession(StandardEmailAddress.ADMIN)

        then:
        session

        and: 'logging out'
        PUT('logout', [:])

        then:
        !getToken(session.id)

        and: 'getting folder'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'session timed out folder is not available\''
        verifyResponse(NOT_FOUND, response)
    }

    @Ignore('not coded')
    void 'KEYCLOAK15 - test access after user has been disabled'() {

        when: 'not logged in'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'folder is not available'
        verifyResponse(NOT_FOUND, response)

        when: 'logged in'
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak('mdm-admin', 'mdm-admin')
        POST('login?scheme=openIdConnect', authorizeResponse)
        verifyResponse(OK, response)
        HttpSession session = getSession(StandardEmailAddress.ADMIN)

        then:
        session

        and: 'logging out'
        PUT('logout', [:])

        then:
        !getToken(session.id)

        and: 'getting folder'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'session timed out folder is not available\''
        verifyResponse(NOT_FOUND, response)
    }

    @Ignore('Manual testing only')
    void 'GOOGLE01 - test logging in with valid authentication code and parameters with non-existent user'() {
        given:
        // Manually go to this web URL
        /*
https://accounts.google.com/o/oauth2/v2/auth?scope=openid+email&response_type=code
&state=9329705d-3cd0-4a59-b588-a369d72aaeae
&nonce=%7CF%7F%EF%BF%BD%5B5%EF%BF%BD%2F%EF%BF%BD%EF%BF%BD%EF%BF%BD%EF%BF%BD%22%EF%BF%BD%C3%9FR%EF%BF%BD%13%EF%BF%BD%EF%BF%BD%D9%AC%EF%BF%BD%00%E0%BA%BA%7B%EF%BF%BDrj
&client_id=375980182300-tc8sb8c1jelomnkmvqtkkqpl4g8lkp06.apps.googleusercontent.com
&redirect_uri=https://jenkins.cs.ox.ac.uk
        */
        // Get the redirected URL
        /*
        https://jenkins.cs.ox.ac.uk/?
        state=9329705d-3cd0-4a59-b588-a369d72aaeae
        &code=
        &scope=email+openid+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email
        &authuser=0
        &prompt=consent
        */
        // Extract the code and session_state param and put in the map below
        // Run the test
        // Each time you run you will need to get a new code
        //
        // Comment out line 50 in OpenidConnectIdTokenJwtVerifier otherwise the token validation wont work
        Map<String, String> authorizeResponse = [
            openidConnectProviderId: googleProvider.id.toString(),
            nonce                  : urlEncodedNonce,
            redirect_uri           : 'https://jenkins.cs.ox.ac.uk',
            state                  : '9329705d-3cd0-4a59-b588-a369d72aaeae',
            session_state          : '',
            code                   : '',
        ]

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(OK, response)

        when: 'check user has been created'
        CatalogueUser user = getUser('ollie.freeman@gmail.com')

        then:
        user
        user.firstName == 'Ollie'
        user.lastName == 'Freeman'
        user.createdBy == 'openidConnectAuthentication@jenkins.cs.ox.ac.uk'
    }

    @Ignore('Manual testing only')
    void 'AZURE01 - test logging in with valid authentication code and parameters with user'() {
        given:
        // You will need to populate the following to create the azure provider
        // clientId is the "Application (client) ID"
        // tenantId is the "Directory (tenant) ID"
        // clientSecret is from creating a new secret
        OpenidConnectProvider azureProvider = createAzureProvider(
            'https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration',
            '06a7cf73-c0a1-4ecc-9b6a-10f389331525',
            'df.7Q~KU6TjBhilGQW45ZtruZBMTe98bpxjoh',
            'bc88d555-3533-4d23-a99b-9f034c0fe6fe')
        assert azureProvider.id

        // Manually go to this web URL (populate the client id)
        /*
https://login.microsoftonline.com/bc88d555-3533-4d23-a99b-9f034c0fe6fe/oauth2/v2.0/authorize?scope=openid+email+profile&response_type=code&state=402d42f8-56fc-46f3-b6c2-4303fdaff689&nonce=%7CF%7F%EF%BF%BD%5B5%EF%BF%BD%2F%EF%BF%BD%EF%BF%BD%EF%BF%BD%EF%BF%BD%22%EF%BF%BD%C3%9FR%EF%BF%BD%13%EF%BF%BD%EF%BF%BD%D9%AC%EF%BF%BD%00%E0%BA%BA%7B%EF%BF%BDrjc&client_id=06a7cf73-c0a1-4ecc-9b6a-10f389331525&redirect_uri=https://jenkins.cs.ox.ac.uk
        */
        // Get the redirected URL
        /*
        https://jenkins.cs.ox.ac.uk/?
        code=
        &session_state=
        */
        // Extract the code and session_state param and put in the map below
        // Run the test
        // Each time you run you will need to get a new code
        //
        // Comment out line 50 in OpenidConnectIdTokenJwtVerifier otherwise the token validation wont work
        Map<String, String> authorizeResponse = [
            openidConnectProviderId: azureProvider.id.toString(),
            nonce                  : new String(nonce),
            redirect_uri           : 'https://jenkins.cs.ox.ac.uk',
            state                  : '402d42f8-56fc-46f3-b6c2-4303fdaff689',
            session_state          : '71ec1bf4-b1ce-4ccf-8f6a-eb0b60580f4a',
            code                   : '0.AS8AVdWIvDM1I02pm58DTA_m_nPPpwahwMxOm2oQ84kzFSUvAKc.AQABAAIAAAD--DLA3VO7QrddgJg7WevrMx59GcOKw2uCwZl9KNPM4BXQPsJ6oP2G8TucnveJhWiLMk0LGyrnp5a8xO_GmPdPDWvipbbEQu8Z07lvkhq0XtJ1ztVUP3wvDjtNm2R828_Mo1CxJmBHEDl768EZzRoE2B8wrXrAZPt_b9_CKRAOZAV8nJQOF2Xl3DlHvjNB9xu4yiNCkou-51JfkS5mieUhvr7Ptk9rFxaje4FC5x0CDvO6TlsY7AVGZIthUd6I5f3DE04TaYDskHsRi3DQ6K9Rfm6BhwJQ7-g-BUfW6AVKawspAhtLMgLvD-v14EF2J5qdjjSIeoKlDdyA-sDitVSbDpgEeL2yRaE0ufdDmMeC1kRjyWNYdPSUCsAYXBhusRPutgxe96NGiBkIpVR7c8tlPp_FMsF_j1jFddMqE-hOBSXR-2OotVA4RGdlZ2ILTvOPeGlU_huxfKtrjf8sgDzz1emdPToiwYG77kKImzd8ZbXjaIyspUv0TuMUnCLcYzE8NGYCFHSP91hX65mFMW6YIkT8dNY43VKiJOKepxJPEAyB9DVTECy1fPJGqj1mFbq_ocNPbBdw0ar42Tca8hB1I2vMuWSRYJvsjedUct51aE_ouuVz4V4uCY6xBVXNMcYoR2tdYrcK1xTVeXU023mH1fy9AWyglUeku9h_hUJMPSVfSv-gM1ovCkXm1z34YAJv-Sg3tzOuRrCRdEz_I8gWC2cs6c8Hiw5mpPtBIrY9rem_t_S4QLbC5b0iu6-M77nuAELbA2MHBrMuwmigpAQ4ljxdJogHR_Y4UJn9VE3Xtw2DBh5ZJtoURiPdTk2vdqDaqSCmJ4KsduhWjt8dwdih5bdLAYXiC8gBSfFZybES1YKabwRhv9bPPHelCCbxaWAg2SwIyVDCv4HFV_RShxvbdDdcxG0oDbsvq9oDZNtZiN7NB6gkG0KzrvuCgWBU5LH2kXkcM1Nw8Tm-fkeid7BMRkkN8z1AUzmdB2uwilycaRmFfXCVU9bA_RSQN4mzCW66PszLLVdRO7k5dKI3EnRm62NbdeU5hVStXtOgrva53b7cGYMpfmdJ84TbB-4IPpMQcWHtimm-r0vvyipwwxQLQS3f4jcZyvBRRO4UbOjYvsIAvtEaeDNaeeO4IG4uS-QvQi5jTgVyWy1Aqxot9iiZUngSJRFJ85UvY9XpaovZkPDZP04kwtqXfhEHhxcwcl3ctv8PcA8nBihRTBwm546VqUd-CdQtwz8um7lG6pYZPwHL7ObWYYYpn4HxmQimbzkgAA',
        ]

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(OK, response)

        when: 'check user has been created'
        CatalogueUser user = getUser('maurodatamapper@outlook.com')

        then:
        user
        user.firstName == 'Oliver'
        user.lastName == 'Freeman'
        user.createdBy == 'openidConnectAuthentication@login.microsoftonline.com'
    }

    Map<String, String> authoriseAgainstKeyCloak(String username = 'mdm-admin', String password = 'mdm-admin', String nonce = null) {
        Map<String, Object> documentData = getAuthoriseDocument(keycloakProvider, nonce)

        // Get the login form and complete it
        FormElement form = (documentData.document as Document).getElementById('kc-form-login') as FormElement
        form.getElementById('username').val(username)
        form.getElementById('password').val(password)

        // Setup connection to submit form for authentication
        // We MUST submit the cookies from the authorise request along with the authenticate
        Connection connection = form.submit()
            .header('accept', '*/*')
            .cookies(documentData.cookies as Map<String, String>)

        // Execute and get the response
        // The response "url" will hold all the params we need to pass for token request
        Connection.Response response = connection.execute()

        // Get all the parameters we got back from authenticate
        Map<String, String> authenticateParameters = response.url().query.split('&').collectEntries {it.split('=')}
        authenticateParameters.openidConnectProviderId = keycloakProvider.id.toString()
        authenticateParameters.redirectUri = documentData.redirectUrl
        authenticateParameters.sessionState = authenticateParameters.session_state
        authenticateParameters
    }

    Map<String, Object> getAuthoriseDocument(OpenidConnectProvider provider, String nonce) {
        String authoriseEndpoint

        if (!nonce) {
            // We need to get the session generated nonce in the URL so we need to make a proper request
            // Lovely proof that the system is secure against replay
            HttpResponse<List<Map>> localResponse = GET('openidConnectProviders', Argument.listOf(Map), true)

            // Connect and then request the authorise page from KC
            authoriseEndpoint = localResponse.body().find {it.label == provider.label}.authorizationEndpoint
        } else {
            // Fake a sessionid for authorisation which will result in different nonce values on token request
            authoriseEndpoint = provider.getFullAuthorizationEndpointUrl(nonce)
        }

        // Get all the parameters we sent to authorise
        Map<String, String> authorizeParameters = authoriseEndpoint.toURL().query.split('&').collectEntries {it.split('=')}

        // Pull out the nonce
        String redirectUrl = "https://jenkins.cs.ox.ac.uk"
        String authoriseEndpointWithRedirect = "${authoriseEndpoint}&redirect_uri=${URLEncoder.encode(redirectUrl, 'UTF-8')}"

        Connection authoriseConnection = Jsoup.connect(authoriseEndpointWithRedirect)
        [document   : authoriseConnection.get(),
         cookies    : authoriseConnection.response().cookies(),
         redirectUrl: redirectUrl,
        ]
    }

    Map<String, String> getResponseBody(String providerId, String code) {
        getResponseBody(providerId, code, UUID.randomUUID().toString(), UUID.randomUUID().toString(), UUID.randomUUID().toString())
    }

    Map<String, String> getResponseBody(String providerId, String code, String sessionState, String nonce, String state) {
        [
            openidConnectProviderId: providerId,
            code                   : code,
            session_state          : sessionState,
            state                  : state,
            redirect_uri           : 'https://jenkins.cs.ox.ac.uk',
            nonce                  : nonce
        ]
    }

    HttpSession getSession(String emailAddress) {
        servletContext.getAttribute(SessionService.CONTEXT_PROPERTY_NAME).values().find {it.getAttribute('emailAddress') == emailAddress}
    }

    Date getExpiredTime() {
        Date now = new Date()
        new Date(now.getTime() - 100000)
    }
}

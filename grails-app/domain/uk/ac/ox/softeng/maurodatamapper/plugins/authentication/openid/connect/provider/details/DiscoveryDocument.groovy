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

import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.traits.domain.MdmDomain

class DiscoveryDocument implements MdmDomain{

    UUID id
    String issuer
    String authorizationEndpoint
    String tokenEndpoint
    String userinfoEndpoint
    String endSessionEndpoint
    String jwksUri

    static belongsTo = [
        openidConnectProvider: OpenidConnectProvider
    ]

    static constraints = {
        issuer blank: false, url: true
        authorizationEndpoint blank: false, url: true
        tokenEndpoint blank: false, url: true
        userinfoEndpoint blank: false, url: true, nullable: true
        endSessionEndpoint blank: false, url: true, nullable: true
        jwksUri blank: false, url: true
        path nullable: true
    }

    @Override
    String getDomainType() {
        DiscoveryDocument.simpleName
    }

    @Override
    String getPathPrefix() {
        return null
    }

    @Override
    String getPathIdentifier() {
        return null
    }
}

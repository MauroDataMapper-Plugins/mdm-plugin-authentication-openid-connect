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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.security

import uk.ac.ox.softeng.maurodatamapper.security.utils.SecurityUtils

import groovy.util.logging.Slf4j

/**
 * @since 02/11/2021
 */
@Slf4j
class Utils extends SecurityUtils{

   static String generateNonceUuid(String sessionId){
        byte[] securelyRandomBytes = getHash(sessionId)
        String nonce = UUID.nameUUIDFromBytes(securelyRandomBytes).toString()
       log.trace('Generated nonce for {} as {}', sessionId, nonce)
       nonce
    }
}

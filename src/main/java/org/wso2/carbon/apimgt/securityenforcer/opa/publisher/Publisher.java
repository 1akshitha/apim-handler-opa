/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.apimgt.securityenforcer.opa.publisher;

import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityException;

/**
 * Interface through which data is published to API Security Enforcer. Three implementations of this interface provides
 * the three modes of operations (Async,Sync,Hybrid). Implementations of this
 * interface never returns false when a failure occurs. All errors
 * are signaled by throwing an SecurityException.
 */
public interface Publisher {

    /**
     * Handler publish request meta data to the API Security Enforcer using this method. If the request is properly
     * sent to the OPA server and the response code is the success code, this method should return true. This will never
     * return false. if the OPA server response code is not the success code, method should throw an SecurityException.
     * For all unexpected error conditions, this method must throw an SecurityException.
     *
     * @param requestMetaData Meta data extracted from the client request in the format which OPA Server supports
     * @param correlationID   The unique ID for the request.
     * @return true if the authentication is successful (In Async Implementation, if not available in cache,
     * this returns through without considering the OPA Server response)
     * @throws SecurityException If an request failure or some other error occurs
     */
    boolean verifyRequest(JSONObject requestMetaData, String correlationID) throws SecurityException;

}

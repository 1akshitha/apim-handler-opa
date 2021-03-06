/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.apimgt.securityenforcer.opa.internal;

import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.securityenforcer.opa.dto.SecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.opa.publisher.HttpDataPublisher;
import org.wso2.carbon.apimgt.securityenforcer.opa.publisher.Publisher;

public class ServiceReferenceHolder {

    private static final ServiceReferenceHolder instance = new ServiceReferenceHolder();

    private SecurityHandlerConfig securityHandlerConfig;
    private volatile Publisher requestPublisher;
    private volatile HttpDataPublisher httpDataPublisher;
    private JSONObject managementAPIPayload;

    private ServiceReferenceHolder() {

    }

    public static ServiceReferenceHolder getInstance() {

        return instance;
    }

    public SecurityHandlerConfig getSecurityHandlerConfig() {

        return securityHandlerConfig;
    }

    public void setSecurityHandlerConfig(SecurityHandlerConfig securityHandlerConfig) {

        this.securityHandlerConfig = securityHandlerConfig;
    }

    public Publisher getRequestPublisher() {

        return requestPublisher;
    }

    public void setRequestPublisher(Publisher requestPublisher) {

        this.requestPublisher = requestPublisher;
    }

    public HttpDataPublisher getHttpDataPublisher() {

        return httpDataPublisher;
    }

    public void setHttpDataPublisher(HttpDataPublisher httpDataPublisher) {

        this.httpDataPublisher = httpDataPublisher;
    }

    public JSONObject getManagementAPIPayload() {

        return managementAPIPayload;
    }

    public void setManagementAPIPayload(JSONObject managementAPIPayload) {

        this.managementAPIPayload = managementAPIPayload;
    }
}

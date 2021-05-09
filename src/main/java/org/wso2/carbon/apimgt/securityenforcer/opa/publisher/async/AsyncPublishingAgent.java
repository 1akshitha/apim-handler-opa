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

package org.wso2.carbon.apimgt.securityenforcer.opa.publisher.async;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.securityenforcer.opa.OPAResponseStore;
import org.wso2.carbon.apimgt.securityenforcer.opa.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.opa.publisher.HttpDataPublisher;
import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityException;
import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityHandlerConstants;
import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityUtils;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

/**
 * This class is responsible for executing data publishing logic. This class implements runnable interface and
 * need to execute using thread pool executor. Primary task of this class it is accept message context as parameter
 * and perform time consuming data extraction and verifyRequest event to data publisher. Having data extraction and
 * transformation logic in this class will help to reduce overhead added to main message flow.
 */
public class AsyncPublishingAgent implements Runnable {

    private static final Log log = LogFactory.getLog(AsyncPublishingAgent.class);

    private HttpDataPublisher httpDataPublisher;
    private JSONObject requestBody;
    private String correlationID;
    private boolean tenantFlowStarted = false;
    private String tenantDomain;

    AsyncPublishingAgent() {

        httpDataPublisher = getHttpDataPublisher();
    }

    /**
     * This method will clean data references. This method should call whenever we return data process and verifyRequest
     * agent back to pool. Every time when we add new property we need to implement cleaning logic as well.
     */
    void clearDataReference() {

        this.requestBody = null;
        this.correlationID = null;
        this.tenantDomain = null;
    }

    /**
     * This method will use to set message context.
     */
    void setDataReference(JSONObject requestBody, String correlationID, String tenantDomain) {

        this.requestBody = requestBody;
        this.correlationID = correlationID;
        this.tenantDomain = tenantDomain;

    }

    public void run() {

        boolean serverResponse = httpDataPublisher.publish(this.requestBody, this.correlationID);
        String operationMode = ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().getMode();
        startTenantFlow();
        if (SecurityHandlerConstants.ASYNC_MODE_STRING.equals(operationMode)){
            try {
                // This is to check whether we have to update the cache or not. If server response was to block the request, an exception will be thrown.
                SecurityUtils.verifServerResponse(serverResponse, correlationID, "Async Publisher");
                if (log.isDebugEnabled()) {
                    log.debug("Server response was not to block the request " + this.correlationID);
                }
                //If the cached response was to block the request, we have to update it as now server response is not to block
                SecurityUtils.verifyPropertiesWithCache(requestBody, correlationID);
            } catch (SecurityException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Server or cached response was to block the request " + this.correlationID + ". Block lists will be updated.");
                }
                //In Async mode, only a block list will be maintained.
                OPAResponseStore.updateCache(requestBody, serverResponse, correlationID);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Hybrid publisher will update the server response in the cache as " + serverResponse
                        + " for the request " + this.correlationID);
            }
            //In Hybrid mode, both block and allow lists will be maintained
            OPAResponseStore.updateCache(requestBody, serverResponse, correlationID);
        }
        if (tenantFlowStarted) {
            endTenantFlow();
        }
    }

    private HttpDataPublisher getHttpDataPublisher() {

        return ServiceReferenceHolder.getInstance().getHttpDataPublisher();
    }

    private void endTenantFlow() {
        PrivilegedCarbonContext.endTenantFlow();
    }

    private void startTenantFlow() {
        if (this.tenantDomain == null){
            this.tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
        tenantFlowStarted = true;
    }
}


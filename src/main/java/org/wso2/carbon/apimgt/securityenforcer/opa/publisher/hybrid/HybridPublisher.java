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

package org.wso2.carbon.apimgt.securityenforcer.opa.publisher.hybrid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.securityenforcer.opa.OPAResponseStore;
import org.wso2.carbon.apimgt.securityenforcer.opa.publisher.Publisher;
import org.wso2.carbon.apimgt.securityenforcer.opa.publisher.async.AsyncPublisher;
import org.wso2.carbon.apimgt.securityenforcer.opa.publisher.sync.SyncPublisher;
import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityException;
import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityUtils;

public class HybridPublisher implements Publisher {

    private static final Log log = LogFactory.getLog(HybridPublisher.class);
    private AsyncPublisher asyncPublisher;
    private SyncPublisher syncPublisher;

    public HybridPublisher() {

        syncPublisher = new SyncPublisher();
        asyncPublisher = new AsyncPublisher();
        log.info("Hybrid publisher instance created for OPA Security Handler");
    }

    @Override
    public boolean verifyRequest(JSONObject requestMetaData, String correlationID) throws SecurityException {

        boolean serverResponse;
        try {
            boolean cachedOPAResponseAvailable = SecurityUtils.verifyPropertiesWithCache(requestMetaData,
                    correlationID);
            if (!cachedOPAResponseAvailable) {
                if (log.isDebugEnabled()) {
                    log.debug("Cached OPA response is not available for the request " + correlationID
                            + " hence SYNC mode used");
                }
                //A Cached response is not available for token, ip or cookie. Therefore sync mode is used
                serverResponse = syncPublisher.publishSyncEvent(requestMetaData, correlationID);
                OPAResponseStore.updateCache(requestMetaData, serverResponse, correlationID);
                SecurityUtils.verifServerResponse(serverResponse, correlationID, "Sync Publisher");
            } else {
                //A Cached response is available for a one or all of the properties and non of them is to block the
                // request. Async mode is used.
                if (log.isDebugEnabled()) {
                    log.debug("Cached OPA response is available for the request " + correlationID
                            + " hence ASYNC mode used");
                }
                asyncPublisher.publishAsyncEvent(requestMetaData, correlationID);
            }
        } catch (SecurityException e) {
            // if cached response is to block the request, there will be an exception and cache will be updated
            // with a new async sideband call
            if (log.isDebugEnabled()) {
                log.debug("Cached OPA response is to block the request " + correlationID);
            }
            asyncPublisher.publishAsyncEvent(requestMetaData, correlationID);
            throw e;
        }
        return true;
    }

    public void setAsyncPublisher(AsyncPublisher asyncPublisher) {

        this.asyncPublisher = asyncPublisher;
    }

    public void setSyncPublisher(SyncPublisher syncPublisher) {

        this.syncPublisher = syncPublisher;
    }
}

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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.apimgt.securityenforcer.opa.dto.SecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.opa.publisher.HttpDataPublisher;
import org.wso2.carbon.apimgt.securityenforcer.opa.publisher.Publisher;
import org.wso2.carbon.apimgt.securityenforcer.opa.publisher.async.AsyncPublisher;
import org.wso2.carbon.apimgt.securityenforcer.opa.publisher.async.AsyncPublisherThreadPool;
import org.wso2.carbon.apimgt.securityenforcer.opa.publisher.sync.SyncPublisher;
import org.wso2.carbon.apimgt.securityenforcer.opa.publisher.sync.SyncPublisherThreadPool;
import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityException;
import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityHandlerConstants;
import org.wso2.carbon.apimgt.securityenforcer.opa.publisher.hybrid.HybridPublisher;
import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityHandlerConfiguration;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.IOException;

@Component(name = "org.wso2.carbon.apimgt.securityenforcer", immediate = true)
public class SecurityHandlerComponent implements BundleActivator {

    private static final Log log = LogFactory.getLog(SecurityHandlerComponent.class);

    private String operationMode;
    private HttpDataPublisher httpDataPublisher;
    private SecurityHandlerConfig securityHandlerConfig;

    public void start(BundleContext bundleContext) throws Exception {

        log.debug("OSGi start method for OPA security handler");

        securityHandlerConfig = getConfigData();
        ServiceReferenceHolder.getInstance().setSecurityHandlerConfig(securityHandlerConfig);

        if (securityHandlerConfig.isPolicyEnforcementEnabled()) {
            logConfigData(securityHandlerConfig);
            operationMode = securityHandlerConfig.getMode();

            Publisher requestPublisher;
            Publisher responsePublisher;

            switch (operationMode) {
                case SecurityHandlerConstants.SYNC_MODE_STRING:
                    requestPublisher = new SyncPublisher();
                    break;
                case SecurityHandlerConstants.ASYNC_MODE_STRING:
                    requestPublisher = new AsyncPublisher();
                    break;
                case SecurityHandlerConstants.HYBRID_MODE_STRING:
                    requestPublisher = new HybridPublisher();
                    break;
                default:
                    throw new Exception("Operation mode is incorrect for OPA Security Handler");
            }
            ServiceReferenceHolder.getInstance().setRequestPublisher(requestPublisher);

            try {
                httpDataPublisher = new HttpDataPublisher(securityHandlerConfig);
            } catch (SecurityException e) {
                log.error("Error when creating a httpDataPublisher Instance " + e.getMessage());
                throw new Exception(e);
            }

            ServiceReferenceHolder.getInstance().setHttpDataPublisher(httpDataPublisher);
        } else {
            log.info("OPA security handler policy enforcement disabled");
        }
    }

    public void stop(BundleContext bundleContext) {

        if (securityHandlerConfig.isPolicyEnforcementEnabled()) {
            log.info("OSGi stop method for OPA Security Handler");
            if (SecurityHandlerConstants.ASYNC_MODE_STRING.equals(operationMode)) {
                log.info("Cleaning the Async thread pool");
                AsyncPublisherThreadPool.getInstance().cleanup();
            } else {
                log.info("Cleaning both Async and sync thread pools");
                AsyncPublisherThreadPool.getInstance().cleanup();
                SyncPublisherThreadPool.getInstance().cleanup();
            }

            try {
                log.info("Closing the Http Client");
                httpDataPublisher.getHttpClient().close();
            } catch (IOException e) {
                log.error("Error when closing the HttpClient");
            }
        }
    }

    /**
     * This method will read the config file.
     */
    private SecurityHandlerConfig getConfigData() throws SecurityException {

        SecurityHandlerConfiguration configuration = new SecurityHandlerConfiguration();
        configuration.load(CarbonUtils.getCarbonConfigDirPath() + File.separator
                + SecurityHandlerConstants.CONFIG_FILE_NAME);
        return configuration.getSecurityHandlerProperties();
    }

    private void logConfigData(SecurityHandlerConfig securityHandlerConfig) {

        if (log.isDebugEnabled()) {
            if (securityHandlerConfig != null) {
                String logMessage = "OPA Security handler configurations- ";
                logMessage = logMessage + ", Operation Mode: " + securityHandlerConfig.getMode();
                logMessage = logMessage + ", Cache Expiry time: " + securityHandlerConfig.getCacheExpiryTime();
                logMessage = logMessage + ", Server Endpoint: " + securityHandlerConfig.getServerConfig().getEndPoint();
                logMessage =
                        logMessage + ", DataPublisher- MaxPerRoute: " + securityHandlerConfig.getDataPublisherConfig()
                                .getMaxPerRoute();
                logMessage = logMessage + ", DataPublisher- MaxOpenConnections: " + securityHandlerConfig
                        .getDataPublisherConfig().getMaxOpenConnections();
                logMessage = logMessage + ", DataPublisher- ConnectionTimeout: " + securityHandlerConfig
                        .getDataPublisherConfig().getConnectionTimeout();
                logMessage = logMessage + ", ThreadPoolExecutor- CorePoolSize: " + securityHandlerConfig
                        .getThreadPoolExecutorConfig().getCorePoolSize();
                logMessage = logMessage + ", ThreadPoolExecutor- MaximumPoolSize: " + securityHandlerConfig
                        .getThreadPoolExecutorConfig().getMaximumPoolSize();
                logMessage = logMessage + ", ThreadPoolExecutor- KeepAliveTime: " + securityHandlerConfig
                        .getThreadPoolExecutorConfig().getKeepAliveTime();
                logMessage =
                        logMessage + ", StackObjectPool- MaxIdle: " + securityHandlerConfig.getStackObjectPoolConfig()
                                .getMaxIdle();
                logMessage = logMessage + ", StackObjectPool- InitIdleCapacity: " + securityHandlerConfig
                        .getStackObjectPoolConfig().getInitIdleCapacity();
                log.debug(logMessage);
            }
        }
    }
}

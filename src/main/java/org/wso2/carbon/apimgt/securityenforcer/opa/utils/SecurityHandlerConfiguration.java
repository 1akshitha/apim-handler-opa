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

package org.wso2.carbon.apimgt.securityenforcer.opa.utils;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axis2.util.JavaUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.securityenforcer.opa.dto.SecurityHandlerConfig;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.securevault.SecretResolver;
import org.wso2.securevault.SecretResolverFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.Stack;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

/**
 * Global API Manager configuration. This is generally populated from a special
 * XML descriptor file at system startup. Once successfully populated, this
 * class does not allow more parameters to be added to the configuration. The
 * design of this class has been greatly inspired by the ServerConfiguration
 * class in Carbon core. This class uses a similar '.' separated approach to
 * keep track of XML parameters.
 */
public class SecurityHandlerConfiguration {

    private static final String RECEIVER_URL_PORT = "receiver.url.port";
    private static final String AUTH_URL_PORT = "auth.url.port";
    private static final String JMS_PORT = "jms.port";
    private static final Log log = LogFactory.getLog(SecurityHandlerConfiguration.class);
    private SecretResolver secretResolver;

    private boolean initialized;
    private SecurityHandlerConfig securityHandlerConfig = new SecurityHandlerConfig();

    /**
     * Populate this configuration by reading an XML file at the given location.
     * This method can be executed only once on a given SecurityHandlerConfiguration
     * instance. Once invoked and successfully populated, it will ignore all
     * subsequent invocations.
     *
     * @param filePath Path of the XML descriptor file
     */

    public void load(String filePath) throws SecurityException {

        if (initialized) {
            return;
        }
        InputStream in = null;
        int offset = getPortOffset();
        int receiverPort = 9611 + offset;
        int authUrlPort = 9711 + offset;
        int jmsPort = 5672 + offset;
        System.setProperty(RECEIVER_URL_PORT, "" + receiverPort);
        System.setProperty(AUTH_URL_PORT, "" + authUrlPort);
        System.setProperty(JMS_PORT, "" + jmsPort);
        try {
            in = FileUtils.openInputStream(new File(filePath));
            StAXOMBuilder builder = new StAXOMBuilder(in);
            secretResolver = SecretResolverFactory.create(builder.getDocumentElement(), true);
            readChildElements(builder.getDocumentElement(), new Stack<String>());
            initialized = true;
        } catch (XMLStreamException | IOException e) {
            log.error("Error when reading the config file ", e);
            throw new SecurityException(SecurityException.HANDLER_ERROR, SecurityException.HANDLER_ERROR_MESSAGE,
                    e);
        } finally {
            if (in != null) {
                IOUtils.closeQuietly(in);
            }
        }
    }

    private void readChildElements(OMElement serverConfig, Stack<String> nameStack) throws SecurityException {

        for (Iterator childElements = serverConfig.getChildElements(); childElements.hasNext(); ) {
            OMElement element = (OMElement) childElements.next();
            String localName = element.getLocalName();
            nameStack.push(localName);

            if (SecurityHandlerConstants.OPA_SECURITY_HANDLER_CONFIGURATION.equals(localName)) {
                try {
                    setSecurityHandlerProperties(serverConfig);
                } catch (Exception e) {
                    log.error("Security Handler config error", e);
                    throw new SecurityException(SecurityException.HANDLER_ERROR,
                            SecurityException.HANDLER_ERROR_MESSAGE, e);
                }
            }
            nameStack.pop();
        }
    }

    public SecurityHandlerConfig getSecurityHandlerProperties() {

        return securityHandlerConfig;
    }

    /**
     * set the AI Security Enforcer Properties into Configuration
     *
     * @param element
     */
    private void setSecurityHandlerProperties(OMElement element) throws SecurityException {

        OMElement opaServerConfigElement = null;
        OMElement opaEndPointElement = null;
        OMElement securityConfigurationElement = element
                .getFirstChildWithName(new QName(SecurityHandlerConstants.OPA_SECURITY_HANDLER_CONFIGURATION));
        if (securityConfigurationElement != null) {

            // Get mode
            OMElement modeElement = securityConfigurationElement
                    .getFirstChildWithName(new QName(SecurityHandlerConstants.OPERATION_MODE_CONFIGURATION));
            if (modeElement != null) {
                securityHandlerConfig.setMode(modeElement.getText());
            } else {
                log.info("Operation mode is not set. Set to default async mode");
            }

            // Get Cache expiry time
            OMElement cacheExpiryElement = securityConfigurationElement
                    .getFirstChildWithName(new QName(SecurityHandlerConstants.CACHE_EXPIRY_TIME_CONFIG));
            if (cacheExpiryElement != null) {
                securityHandlerConfig.setCacheExpiryTime(Integer.parseInt(cacheExpiryElement.getText()));
            } else {
                log.debug("Cache expiry is not set. Set to default: " + securityHandlerConfig.getCacheExpiryTime());
            }

            // Get skip certificate validation
            OMElement skipCertValifationElement = securityConfigurationElement
                    .getFirstChildWithName(new QName(SecurityHandlerConstants.SKIP_CERT_VALIDATION_CONFIG));
            if (skipCertValifationElement != null) {
                securityHandlerConfig
                        .setSkipCertValidation(JavaUtils.isTrueExplicitly(skipCertValifationElement.getText()));
            } else {
                log.debug("Skip Certificate Validation Element is not set. Set to default: "
                        + securityHandlerConfig.isSkipCertValidation());
            }

            // Get default action if policy not found
            OMElement defaultActionPolicyNotFoundElement = securityConfigurationElement
                    .getFirstChildWithName(new QName(SecurityHandlerConstants.POLICY_NOT_FOUND_CONFIG));
            if (defaultActionPolicyNotFoundElement != null) {
                securityHandlerConfig
                        .setDefaultActionIfPolicyNotFound(
                                !JavaUtils.isTrueExplicitly(defaultActionPolicyNotFoundElement.getText()));
            } else {
                log.debug("Default action for policy not found is not set. Set to default: "
                        + securityHandlerConfig.getDefaultActionIfPolicyNotFound());
            }

            // Get default action if server unreachable
            OMElement defaultActionServerUnreachableElement = securityConfigurationElement
                    .getFirstChildWithName(new QName(SecurityHandlerConstants.SERVER_UNREACHABLE_CONFIG));
            if (defaultActionServerUnreachableElement != null) {
                securityHandlerConfig
                        .setDefaultActionIfServerNotReachable(
                                !JavaUtils.isTrueExplicitly(defaultActionServerUnreachableElement.getText()));
            } else {
                log.debug("Default action for server unreachable is not set. Set to default: "
                        + securityHandlerConfig.getDefaultActionIfPolicyNotFound());
            }

            // Get OPA server config data
            opaServerConfigElement = securityConfigurationElement
                    .getFirstChildWithName(new QName(SecurityHandlerConstants.OPA_SERVER_CONFIGURATION));
            SecurityHandlerConfig.ServerConfig serverConfig = new SecurityHandlerConfig.ServerConfig();
            if (opaServerConfigElement != null) {
                opaEndPointElement = opaServerConfigElement
                        .getFirstChildWithName(new QName(SecurityHandlerConstants.END_POINT_CONFIGURATION));
                if (opaEndPointElement != null) {
                    serverConfig.setEndPoint(opaEndPointElement.getText());
                } else {
                    log.error("Security handler config error - OPA Server Endpoint not found");
                    throw new SecurityException(SecurityException.HANDLER_ERROR,
                            SecurityException.HANDLER_ERROR_MESSAGE);
                }

                OMElement backupServerEndPointElement = opaServerConfigElement.getFirstChildWithName(
                        new QName(SecurityHandlerConstants.BACKUP_SERVER_END_POINT_CONFIGURATION));
                if (backupServerEndPointElement != null) {
                    serverConfig.setBackupServerEndPoint(backupServerEndPointElement.getText());
                } else {
                    log.debug(
                            "Security handler config error - Backup OPA Server Endpoint not found. Set to primary OPA Server: "
                                    + opaEndPointElement.getText());
                    serverConfig.setBackupServerEndPoint(opaEndPointElement.getText());
                }

                OMElement authTokenElement = opaServerConfigElement
                        .getFirstChildWithName(new QName(SecurityHandlerConstants.AUTH_TOKEN_CONFIGURATION));
                if (authTokenElement != null) {
                    if (secretResolver.isInitialized()
                            && secretResolver.isTokenProtected("APIManager.OPASecurityHandler.Server.OPAAuthToken")) {
                        serverConfig.setAuthToken(
                                secretResolver.resolve("APIManager.OPASecurityHandler.OPAServer.AuthToken"));
                    } else {
                        serverConfig.setAuthToken(authTokenElement.getText());
                    }
                } else {
                    log.error("Security handler config error - OPA Server access token not found");
                }
                securityHandlerConfig.setServerConfig(serverConfig);
            } else {
                log.error("Security handler config error - OPA Server config not found");
                throw new SecurityException(SecurityException.HANDLER_ERROR,
                        SecurityException.HANDLER_ERROR_MESSAGE);
            }

            // Get cache config data
            OMElement cacheConfigElement = securityConfigurationElement
                    .getFirstChildWithName(new QName(SecurityHandlerConstants.CACHE_CONFIGURATION));
            SecurityHandlerConfig.CacheConfig cacheConfig =
                    new SecurityHandlerConfig.CacheConfig();
            if (cacheConfigElement != null) {
                OMElement tokenCacheElement = cacheConfigElement
                        .getFirstChildWithName(new QName(SecurityHandlerConstants.TOKEN_CACHE_CONFIGURATION));
                if (tokenCacheElement != null) {
                    cacheConfig.setTokenCacheEnabled(JavaUtils.isTrueExplicitly(tokenCacheElement.getText()));
                }

                OMElement ipCacheElement = cacheConfigElement
                        .getFirstChildWithName(new QName(SecurityHandlerConstants.IP_CACHE_CONFIGURATION));
                if (ipCacheElement != null) {
                    cacheConfig.setIPCacheEnabled(JavaUtils.isTrueExplicitly(ipCacheElement.getText()));
                }

                OMElement cookieCacheElement = cacheConfigElement
                        .getFirstChildWithName(new QName(SecurityHandlerConstants.COOKIE_CACHE_CONFIGURATION));
                if (cookieCacheElement != null) {
                    cacheConfig.setCookieCacheEnabled(JavaUtils.isTrueExplicitly(cookieCacheElement.getText()));
                }
            } else {
                log.debug("Cache config is not set. Set to default.");
            }
            securityHandlerConfig.setCacheConfig(cacheConfig);

            // Get data publisher config data
            OMElement dataPublisherConfigElement = securityConfigurationElement
                    .getFirstChildWithName(new QName(SecurityHandlerConstants.DATA_PUBLISHER_CONFIGURATION));
            SecurityHandlerConfig.DataPublisherConfig dataPublisherConfig =
                    new SecurityHandlerConfig.DataPublisherConfig();
            if (dataPublisherConfigElement != null) {
                OMElement maxPerRouteElement = dataPublisherConfigElement
                        .getFirstChildWithName(new QName(SecurityHandlerConstants.MAX_PER_ROUTE_CONFIGURATION));
                if (maxPerRouteElement != null) {
                    dataPublisherConfig.setMaxPerRoute(Integer.parseInt(maxPerRouteElement.getText()));
                }

                OMElement maxOpenConnectionsElement = dataPublisherConfigElement.getFirstChildWithName(
                        new QName(SecurityHandlerConstants.MAX_OPEN_CONNECTIONS_CONFIGURATION));
                if (maxOpenConnectionsElement != null) {
                    dataPublisherConfig.setMaxOpenConnections(Integer.parseInt(maxOpenConnectionsElement.getText()));
                }

                OMElement connectionTimeoutElement = dataPublisherConfigElement
                        .getFirstChildWithName(new QName(SecurityHandlerConstants.CONNECTIONS_TIMEOUT_CONFIGURATION));
                if (connectionTimeoutElement != null) {
                    dataPublisherConfig.setConnectionTimeout(Integer.parseInt(connectionTimeoutElement.getText()));
                }
            } else {
                log.debug("Data publisher config is not set. Set to default.");
            }
            securityHandlerConfig.setDataPublisherConfig(dataPublisherConfig);

            // Get thread pool executor config data
            OMElement threadPoolExecutorConfigElement = securityConfigurationElement
                    .getFirstChildWithName(new QName(SecurityHandlerConstants.THREAD_POOL_EXECUTOR_CONFIGURATION));
            SecurityHandlerConfig.ThreadPoolExecutorConfig threadPoolExecutorConfig =
                    new SecurityHandlerConfig.ThreadPoolExecutorConfig();
            if (threadPoolExecutorConfigElement != null) {
                OMElement corePoolSizeElement = threadPoolExecutorConfigElement
                        .getFirstChildWithName(new QName(SecurityHandlerConstants.CORE_POOL_SIZE_CONFIGURATION));
                if (corePoolSizeElement != null) {
                    threadPoolExecutorConfig.setCorePoolSize(Integer.parseInt(corePoolSizeElement.getText()));
                }

                OMElement maximumPoolSizeElement = threadPoolExecutorConfigElement
                        .getFirstChildWithName(new QName(SecurityHandlerConstants.MAX_POOL_SIZE_CONFIGURATION));
                if (maximumPoolSizeElement != null) {
                    threadPoolExecutorConfig.setMaximumPoolSize(Integer.parseInt(maximumPoolSizeElement.getText()));
                }

                OMElement keepAliveTimeElement = threadPoolExecutorConfigElement
                        .getFirstChildWithName(new QName(SecurityHandlerConstants.KEEP_ALIVE_TIME_CONFIGURATION));
                if (keepAliveTimeElement != null) {
                    threadPoolExecutorConfig.setKeepAliveTime(Long.parseLong(keepAliveTimeElement.getText()));
                }
            } else {
                log.debug("Thread pool config is not set. Set to default.");
            }
            securityHandlerConfig.setThreadPoolExecutorConfig(threadPoolExecutorConfig);

            // Get stack object pool config data
            OMElement stackObjectPoolConfigElement = securityConfigurationElement
                    .getFirstChildWithName(new QName(SecurityHandlerConstants.STACK_OBJECT_POOL_CONFIGURATION));
            SecurityHandlerConfig.StackObjectPoolConfig stackObjectPoolConfig =
                    new SecurityHandlerConfig.StackObjectPoolConfig();
            if (stackObjectPoolConfigElement != null) {
                OMElement maxIdleElement = stackObjectPoolConfigElement
                        .getFirstChildWithName(new QName(SecurityHandlerConstants.MAX_IDLE_CONFIGURATION));
                if (maxIdleElement != null) {
                    stackObjectPoolConfig.setMaxIdle(Integer.parseInt(maxIdleElement.getText()));
                }

                OMElement initIdleCapacityElement = stackObjectPoolConfigElement
                        .getFirstChildWithName(new QName(SecurityHandlerConstants.INIT_IDLE_CAPACITY_CONFIGURATION));
                if (initIdleCapacityElement != null) {
                    stackObjectPoolConfig.setInitIdleCapacity(Integer.parseInt(initIdleCapacityElement.getText()));
                }
            } else {
                log.debug("Stack object pool config is not set. Set to default.");
            }
            securityHandlerConfig.setStackObjectPoolConfig(stackObjectPoolConfig);

            if (securityConfigurationElement != null && opaServerConfigElement != null && opaEndPointElement != null) {
                securityHandlerConfig.setPolicyEnforcementEnabled(true);
                log.info("OPA security handler policy enforcement enabled");
            }
        }
    }

    private int getPortOffset() {

        ServerConfiguration carbonConfig = ServerConfiguration.getInstance();
        String portOffset = System.getProperty("portOffset", carbonConfig.getFirstProperty("Ports.Offset"));
        try {
            if ((portOffset != null)) {
                return Integer.parseInt(portOffset.trim());
            } else {
                return 0;
            }
        } catch (NumberFormatException e) {
            log.error("Invalid Port Offset: " + portOffset + ". Default value 0 will be used.", e);
            return 0;
        }
    }

}

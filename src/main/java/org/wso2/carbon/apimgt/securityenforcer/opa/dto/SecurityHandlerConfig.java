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

package org.wso2.carbon.apimgt.securityenforcer.opa.dto;

import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityHandlerConstants;

/**
 * This class contains the config data for Security Handler.
 */

public class SecurityHandlerConfig {

    private boolean policyEnforcementEnabled = false;
    private boolean skipCertValidation = false;
    private String mode = SecurityHandlerConstants.SYNC_MODE_STRING;
    private int cacheExpiryTime = 15;
    private boolean defaultActionIfPolicyNotFound = true;
    private boolean defaultActionIfServerNotReachable = true;
    private ServerConfig serverConfig;
    private CacheConfig cacheConfig;
    private SecurityHandlerConfig.DataPublisherConfig dataPublisherConfig;
    private SecurityHandlerConfig.StackObjectPoolConfig stackObjectPoolConfig;
    private SecurityHandlerConfig.ThreadPoolExecutorConfig threadPoolExecutorConfig;

    public boolean isPolicyEnforcementEnabled() {

        return policyEnforcementEnabled;
    }

    public void setPolicyEnforcementEnabled(boolean policyEnforcementEnabled) {

        this.policyEnforcementEnabled = policyEnforcementEnabled;
    }

    public String getMode() {

        return mode;
    }

    public void setMode(String mode) {

        this.mode = mode;
    }

    public int getCacheExpiryTime() {

        return cacheExpiryTime;
    }

    public void setCacheExpiryTime(int cacheExpiryTime) {

        this.cacheExpiryTime = cacheExpiryTime;
    }

    public boolean isSkipCertValidation() {

        return skipCertValidation;
    }

    public void setSkipCertValidation(boolean skipCertValidation) {

        this.skipCertValidation = skipCertValidation;
    }

    public ServerConfig getServerConfig() {

        return serverConfig;
    }

    public void setServerConfig(ServerConfig serverConfig) {

        this.serverConfig = serverConfig;
    }

    public boolean getDefaultActionIfPolicyNotFound() {

        return defaultActionIfPolicyNotFound;
    }

    public void setDefaultActionIfPolicyNotFound(boolean defaultActionIfPolicyNotFound) {

        this.defaultActionIfPolicyNotFound = defaultActionIfPolicyNotFound;
    }

    public boolean getDefaultActionIfServerNotReachable() {

        return defaultActionIfServerNotReachable;
    }

    public void setDefaultActionIfServerNotReachable(boolean defaultActionIfServerNotReachable) {

        this.defaultActionIfServerNotReachable = defaultActionIfServerNotReachable;
    }

    public CacheConfig getCacheConfig() {

        return cacheConfig;
    }

    public void setCacheConfig(CacheConfig cacheConfig) {

        this.cacheConfig = cacheConfig;
    }

    public DataPublisherConfig getDataPublisherConfig() {

        return dataPublisherConfig;
    }

    public void setDataPublisherConfig(DataPublisherConfig dataPublisherConfig) {

        this.dataPublisherConfig = dataPublisherConfig;
    }

    public ThreadPoolExecutorConfig getThreadPoolExecutorConfig() {

        return threadPoolExecutorConfig;
    }

    public void setThreadPoolExecutorConfig(ThreadPoolExecutorConfig threadPoolExecutorConfig) {

        this.threadPoolExecutorConfig = threadPoolExecutorConfig;
    }

    public StackObjectPoolConfig getStackObjectPoolConfig() {

        return stackObjectPoolConfig;
    }

    public void setStackObjectPoolConfig(StackObjectPoolConfig stackObjectPoolConfig) {

        this.stackObjectPoolConfig = stackObjectPoolConfig;
    }

    public static class ServerConfig {

        private String primaryServerEndPoint;
        private String backupServerEndPoint;
        // currentEndpoint is the server endpoint to which OPASecurityHandler will send the
        // requests to at any point of time.
        private String currentEndpoint;

        private String authToken = "";

        public String getEndPoint() {

            return currentEndpoint;
        }

        /**
         * This method is called only once when the Security Handler configuration is
         * loaded. It will set the primary EndPoint and current Endpoint.
         */
        public void setEndPoint(String endPoint) {

            this.primaryServerEndPoint = endPoint;
            this.currentEndpoint = endPoint;
        }

        /**
         * This method takes currEndpoint as an argument that has resulted in a
         * connection refused or connection timeout exception. If shiftEndpoint receives
         * primaryServerEndPoint as argument, currentEndpoint will be set to
         * backupServerEndPoint. If shiftEndpoint receives backupServerEndPoint as argument,
         * currentEndpoint will be set to primaryServerEndPoint. This method is thread safe
         * since it is synchronized.
         */
        public synchronized void shiftEndpoint(String currEndpoint) {

            if (currEndpoint.equalsIgnoreCase(primaryServerEndPoint)) {
                this.currentEndpoint = backupServerEndPoint;
            } else {
                this.currentEndpoint = primaryServerEndPoint;
            }
        }

        public String getBackupServerEndPoint() {

            return backupServerEndPoint;
        }

        public void setBackupServerEndPoint(String backupServerEndPoint) {

            this.backupServerEndPoint = backupServerEndPoint;
        }

        public String getAuthToken() {

            return authToken;
        }

        public void setAuthToken(String authToken) {

            this.authToken = authToken;
        }
    }

    public static class CacheConfig {

        private boolean tokenCacheEnabled = true;
        private boolean cookieCacheEnabled = true;
        private boolean IPCacheEnabled = true;

        public boolean isTokenCacheEnabled() {

            return tokenCacheEnabled;
        }

        public void setTokenCacheEnabled(boolean tokenCacheEnabled) {

            this.tokenCacheEnabled = tokenCacheEnabled;
        }

        public boolean isCookieCacheEnabled() {

            return cookieCacheEnabled;
        }

        public void setCookieCacheEnabled(boolean cookieCacheEnabled) {

            this.cookieCacheEnabled = cookieCacheEnabled;
        }

        public boolean isIPCacheEnabled() {

            return IPCacheEnabled;
        }

        public void setIPCacheEnabled(boolean IPCacheEnabled) {

            this.IPCacheEnabled = IPCacheEnabled;
        }
    }

    public static class DataPublisherConfig {

        private Integer maxOpenConnections = 500;
        private Integer maxPerRoute = 200;
        private Integer connectionTimeout = 30;

        public Integer getMaxOpenConnections() {

            return maxOpenConnections;
        }

        public void setMaxOpenConnections(Integer maxOpenConnections) {

            this.maxOpenConnections = maxOpenConnections;
        }

        public Integer getMaxPerRoute() {

            return maxPerRoute;
        }

        public void setMaxPerRoute(Integer maxPerRoute) {

            this.maxPerRoute = maxPerRoute;
        }

        public Integer getConnectionTimeout() {

            return connectionTimeout;
        }

        public void setConnectionTimeout(Integer connectionTimeout) {

            this.connectionTimeout = connectionTimeout;
        }
    }

    public static class StackObjectPoolConfig {

        private Integer maxIdle = 100;
        private Integer initIdleCapacity = 50;

        public Integer getMaxIdle() {

            return maxIdle;
        }

        public void setMaxIdle(Integer maxIdle) {

            this.maxIdle = maxIdle;
        }

        public Integer getInitIdleCapacity() {

            return initIdleCapacity;
        }

        public void setInitIdleCapacity(Integer initIdleCapacity) {

            this.initIdleCapacity = initIdleCapacity;
        }
    }

    public static class ThreadPoolExecutorConfig {

        private Integer corePoolSize = 200;
        private Integer maximumPoolSize = 500;
        private Long keepAliveTime = 100L;

        public Integer getCorePoolSize() {

            return corePoolSize;
        }

        public void setCorePoolSize(Integer corePoolSize) {

            this.corePoolSize = corePoolSize;
        }

        public Integer getMaximumPoolSize() {

            return maximumPoolSize;
        }

        public void setMaximumPoolSize(Integer maximumPoolSize) {

            this.maximumPoolSize = maximumPoolSize;
        }

        public Long getKeepAliveTime() {

            return keepAliveTime;
        }

        public void setKeepAliveTime(Long keepAliveTime) {

            this.keepAliveTime = keepAliveTime;
        }
    }

}

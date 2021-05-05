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

package org.wso2.carbon.apimgt.securityenforcer.opa;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.securityenforcer.opa.dto.CacheResponseDTO;
import org.wso2.carbon.apimgt.securityenforcer.opa.dto.SecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.opa.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityHandlerConstants;

import java.util.concurrent.TimeUnit;

import javax.cache.Cache;
import javax.cache.CacheConfiguration;
import javax.cache.Caching;

/**
 * OPAResponseStore class acts as the cache for the Authenticator.
 */

public class OPAResponseStore {

    private static final Log log = LogFactory.getLog(OPAResponseStore.class);
    private static boolean cookieCacheInitialized = false;
    private static boolean tokenCacheInitialized = false;
    private static boolean IPCacheInitialized = false;

    public OPAResponseStore() {}

    public synchronized static void writeToOPAResponseCache(String cacheName, String cacheKey,
                                                            boolean opaResponse) {

        if (cacheKey != null) {
            Cache cache = getCache(cacheName);
            if (cache != null) {
                cache.put(cacheKey, opaResponse);
            }
        }
    }

    public static CacheResponseDTO getFromOPAResponseCache(String cacheName, String cacheKey) {

        CacheResponseDTO cacheResponse = new CacheResponseDTO();
        if (cacheKey != null) {
            Cache cache = getCache(cacheName);
            if (cache != null) {
                Object cachedObject = cache.get(cacheKey);
                if (cachedObject != null) {
                    cacheResponse.setCachedResponse((boolean) cachedObject);
                    cacheResponse.setAvailableInCache(true);
                }
            }
        }
        return cacheResponse;
    }

    public static void updateCache(JSONObject requestBody, boolean opaResponseCode, String correlationID) {

        String token = (String) requestBody.get(SecurityHandlerConstants.TOKEN_KEY_NAME);
        String cookie = (String) requestBody.get(SecurityHandlerConstants.COOKIE_KEY_NAME);
        String ip = (String) requestBody.get(SecurityHandlerConstants.IP_KEY_NAME);

        writeToOPAResponseCache(SecurityHandlerConstants.TOKEN_CACHE_NAME, token, opaResponseCode);
        writeToOPAResponseCache(SecurityHandlerConstants.COOKIE_CACHE_NAME, cookie, opaResponseCode);
        writeToOPAResponseCache(SecurityHandlerConstants.IP_CACHE_NAME, ip, opaResponseCode);
        if (log.isDebugEnabled()) {
            log.debug("Cache updated for " + correlationID + " as  " + opaResponseCode);
        }
    }

    public synchronized static Cache getTokenCache() {

        boolean tokenCacheEnabled =
                ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().getCacheConfig().isTokenCacheEnabled();

        if (tokenCacheEnabled) {
            if (!tokenCacheInitialized) {
                tokenCacheInitialized = true;
                if (log.isDebugEnabled()) {
                    log.debug("New Cache instance created for OPA security handler with the name of " +
                            SecurityHandlerConstants.TOKEN_CACHE_NAME);
                }
                return Caching.getCacheManager(SecurityHandlerConstants.CACHE_MANAGER_NAME)
                        .createCacheBuilder(SecurityHandlerConstants.TOKEN_CACHE_NAME)
                        .setExpiry(CacheConfiguration.ExpiryType.ACCESSED,
                                new CacheConfiguration.Duration(TimeUnit.MINUTES,
                                        ServiceReferenceHolder.getInstance().getSecurityHandlerConfig()
                                                .getCacheExpiryTime()))
                        .setExpiry(CacheConfiguration.ExpiryType.MODIFIED,
                                new CacheConfiguration.Duration(TimeUnit.MINUTES,
                                        ServiceReferenceHolder.getInstance().getSecurityHandlerConfig()
                                                .getCacheExpiryTime()))
                        .setStoreByValue(false).build();
            } else {
                return Caching.getCacheManager(SecurityHandlerConstants.CACHE_MANAGER_NAME).getCache(
                        SecurityHandlerConstants.TOKEN_CACHE_NAME);
            }
        } else {
            return null;
        }
    }

    public synchronized static Cache getIPCache() {
        boolean IPCacheEnabled =
                ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().getCacheConfig().isIPCacheEnabled();
        if (IPCacheEnabled) {
            if (!IPCacheInitialized) {
                IPCacheInitialized = true;
                if (log.isDebugEnabled()) {
                    log.debug("New Cache instance created for OPA security handler with the name of " +
                            SecurityHandlerConstants.IP_CACHE_NAME);
                }
                return Caching.getCacheManager(SecurityHandlerConstants.CACHE_MANAGER_NAME)
                        .createCacheBuilder(SecurityHandlerConstants.IP_CACHE_NAME)
                        .setExpiry(CacheConfiguration.ExpiryType.ACCESSED,
                                new CacheConfiguration.Duration(TimeUnit.MINUTES,
                                        ServiceReferenceHolder.getInstance().getSecurityHandlerConfig()
                                                .getCacheExpiryTime()))
                        .setExpiry(CacheConfiguration.ExpiryType.MODIFIED,
                                new CacheConfiguration.Duration(TimeUnit.MINUTES,
                                        ServiceReferenceHolder.getInstance().getSecurityHandlerConfig()
                                                .getCacheExpiryTime()))
                        .setStoreByValue(false).build();
            } else {
                return Caching.getCacheManager(SecurityHandlerConstants.CACHE_MANAGER_NAME).getCache(
                        SecurityHandlerConstants.IP_CACHE_NAME);
            }
        } else {
            return null;
        }
    }

    public synchronized static Cache getCookieCache() {

        boolean cookieCacheEnabled =
                ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().getCacheConfig().isCookieCacheEnabled();

        if (cookieCacheEnabled) {
            if (!cookieCacheInitialized) {
                cookieCacheInitialized = true;
                if (log.isDebugEnabled()) {
                    log.debug("New Cache instance created for OPA security handler with the name of " +
                            SecurityHandlerConstants.COOKIE_CACHE_NAME);
                }
                return Caching.getCacheManager(SecurityHandlerConstants.CACHE_MANAGER_NAME)
                        .createCacheBuilder(SecurityHandlerConstants.COOKIE_CACHE_NAME)
                        .setExpiry(CacheConfiguration.ExpiryType.ACCESSED,
                                new CacheConfiguration.Duration(TimeUnit.MINUTES,
                                        ServiceReferenceHolder.getInstance().getSecurityHandlerConfig()
                                                .getCacheExpiryTime()))
                        .setExpiry(CacheConfiguration.ExpiryType.MODIFIED,
                                new CacheConfiguration.Duration(TimeUnit.MINUTES,
                                        ServiceReferenceHolder.getInstance().getSecurityHandlerConfig()
                                                .getCacheExpiryTime()))
                        .setStoreByValue(false).build();
            } else {
                return Caching.getCacheManager(SecurityHandlerConstants.CACHE_MANAGER_NAME).getCache(
                        SecurityHandlerConstants.COOKIE_CACHE_NAME);
            }
        } else {
            return null;
        }
    }

    public static Cache getCache(String cacheName) {

        switch (cacheName) {
            case (SecurityHandlerConstants.TOKEN_CACHE_NAME):
                return getTokenCache();
            case (SecurityHandlerConstants.IP_CACHE_NAME):
                return getIPCache();
            case (SecurityHandlerConstants.COOKIE_CACHE_NAME):
                return getCookieCache();
            default:
                return null;
        }
    }
}

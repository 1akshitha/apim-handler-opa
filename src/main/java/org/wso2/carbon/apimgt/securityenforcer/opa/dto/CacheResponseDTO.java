package org.wso2.carbon.apimgt.securityenforcer.opa.dto;

public class CacheResponseDTO {

    private boolean availableInCache = false;
    private boolean cachedResponse = false;

    public boolean isAvailableInCache() {

        return availableInCache;
    }

    public void setAvailableInCache(boolean availableInCache) {

        this.availableInCache = availableInCache;
    }

    public boolean getCachedResponse() {

        return cachedResponse;
    }

    public void setCachedResponse(boolean cachedResponse) {

        this.cachedResponse = cachedResponse;
    }
}

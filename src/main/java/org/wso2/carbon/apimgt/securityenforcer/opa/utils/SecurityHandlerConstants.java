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

package org.wso2.carbon.apimgt.securityenforcer.opa.utils;

public class SecurityHandlerConstants {

    public static final String HTTPS_PROTOCOL = "https";
    public static final String HTTP_PROTOCOL = "http";
    public static final String HTTP_METHOD_STRING = "HTTP_METHOD";
    public static final String API_BASEPATH_STRING = "TransportInURL";
    public static final String JSON_KEY_SOURCE_IP = "source_ip";
    public static final String JSON_KEY_API_CONTEXT = "context";
    public static final String JSON_KEY_SOURCE_PORT = "source_port";
    public static final String JSON_KEY_METHOD = "method";
    public static final String JSON_KEY_API_BASEPATH = "path";
    public static final String JSON_KEY_HTTP_VERSION = "http_version";
    public static final String JSON_KEY_HEADERS = "headers";
    public static final String JSON_KEY_AUTH_CONTEXT = "auth_context";
    public static final String AUTH_TOKEN_HEADER = "Authorization";
    public static final String CACHE_MANAGER_NAME = "OPA_SECURITY_CACHE";
    public static final String TOKEN_CACHE_NAME = "TokenCache";
    public static final String IP_CACHE_NAME = "IPCache";
    public static final String COOKIE_CACHE_NAME = "CookieCache";
    public static final String TOKEN_KEY_NAME = "Token";
    public static final String IP_KEY_NAME = "IP";
    public static final String COOKIE_KEY_NAME = "Cookie";
    public static final String SERVER_PAYLOAD_KEY_NAME = "ServerPayload";
    public static final String INPUT_KEY_NAME = "input";
    public static final String TRANSPORT_HEADER_HOST_NAME = "Host";
    public static final int DUMMY_REQUEST_PORT = 8080;
    public static final int SERVER_RESPONSE_CODE_SUCCESS = 200;
    public static final int SERVER_RESPONSE_BAD_REQUEST = 400;
    public static final int SERVER_RESPONSE_SERVER_ERROR = 500;
    public static final String SYNC_MODE_STRING = "sync";
    public static final String ASYNC_MODE_STRING = "async";
    public static final String HYBRID_MODE_STRING = "hybrid";
    public static final String END_USER_NAME = "api.ut.userName";
    public static final String REQUEST_RECEIVED_TIME = "wso2statistics.request.received.time";
    public static final String AUTHORIZATION = "Authorization";
    public static final String APPLICATION_NAME = "api.ut.application.name";
    public static final String CONFIG_FILE_NAME = "api-manager.xml";
    public static final String AUTHORIZATION_HEADER_NAME = "Authorization";
    public static final String UNAUTHENTICATED_TIER = "Unauthenticated";
    public static final String ALLOW_RULE = "/allow";
    static final String HTTP_VERSION_CONNECTOR = ".";
    static final String API_SECURITY_NS = "http://wso2.org/apimanager/security";
    static final String API_SECURITY_NS_PREFIX = "ams";
    static final String OPA_SECURITY_HANDLER_CONFIGURATION = "OPASecurityHandler";
    static final String OPERATION_MODE_CONFIGURATION = "OperationMode";
    static final String CACHE_EXPIRY_TIME_CONFIG = "CacheExpiryTime";
    static final String SKIP_CERT_VALIDATION_CONFIG = "SkipCertValidation";
    static final String POLICY_NOT_FOUND_CONFIG = "BlockIfPolicyNotFound";
    static final String SERVER_UNREACHABLE_CONFIG = "BlockIfServerUnreachable";
    static final String OPA_SERVER_CONFIGURATION = "OPAServer";
    static final String END_POINT_CONFIGURATION = "EndPoint";
    static final String BACKUP_SERVER_END_POINT_CONFIGURATION = "BackupEndPoint";
    static final String AUTH_TOKEN_CONFIGURATION = "AuthToken";
    static final String CACHE_CONFIGURATION = "Cache";
    static final String TOKEN_CACHE_CONFIGURATION = "TokenCache";
    static final String IP_CACHE_CONFIGURATION = "IPCache";
    static final String COOKIE_CACHE_CONFIGURATION = "CookieCache";
    static final String DATA_PUBLISHER_CONFIGURATION = "DataPublisher";
    static final String MAX_PER_ROUTE_CONFIGURATION = "MaxPerRoute";
    static final String MAX_OPEN_CONNECTIONS_CONFIGURATION = "MaxOpenConnections";
    static final String CONNECTIONS_TIMEOUT_CONFIGURATION = "ConnectionTimeout";
    static final String THREAD_POOL_EXECUTOR_CONFIGURATION = "ThreadPoolExecutor";
    static final String CORE_POOL_SIZE_CONFIGURATION = "CorePoolSize";
    static final String MAX_POOL_SIZE_CONFIGURATION = "MaximumPoolSize";
    static final String KEEP_ALIVE_TIME_CONFIGURATION = "KeepAliveTime";
    static final String STACK_OBJECT_POOL_CONFIGURATION = "StackObjectPool";
    static final String MAX_IDLE_CONFIGURATION = "MaxIdle";
    static final String INIT_IDLE_CAPACITY_CONFIGURATION = "InitIdleCapacity";

    private SecurityHandlerConstants() {

    }

}

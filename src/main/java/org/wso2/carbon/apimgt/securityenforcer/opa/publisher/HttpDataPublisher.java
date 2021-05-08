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

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import org.apache.axis2.util.JavaUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.apache.openjpa.persistence.jest.JSON;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.securityenforcer.opa.dto.SecurityHandlerConfig;
import org.wso2.carbon.apimgt.securityenforcer.opa.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityException;
import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityHandlerConstants;
import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityUtils;

/**
 * HttpDataPublisher class is here to publish request meta data to security
 * server via http requests. This will create a http client and a
 * pool. If proxy is enabled for the endpoint, client is changed accordingly.
 */
public class HttpDataPublisher {

    private static final Log log = LogFactory.getLog(HttpDataPublisher.class);

    private CloseableHttpClient httpClient;
    private String authToken;
    private String endPoint;
    private SecurityHandlerConfig securityHandlerConfig;

    public HttpDataPublisher(SecurityHandlerConfig securityHandlerConfig) throws
            SecurityException {

        String protocol;
        try {
            protocol = new URL(securityHandlerConfig.getServerConfig().getEndPoint()).getProtocol();
        } catch (MalformedURLException e) {
            log.error("Error when getting the OPA Server endpoint protocol", e);
            throw new SecurityException(SecurityException.HANDLER_ERROR, SecurityException.HANDLER_ERROR_MESSAGE,
                    e);
        }
        httpClient = SecurityUtils.getHttpClient(protocol, securityHandlerConfig.getDataPublisherConfig());
        setAuthToken(securityHandlerConfig.getServerConfig().getAuthToken());
        setEndPoint(securityHandlerConfig.getServerConfig().getEndPoint());
        this.securityHandlerConfig = securityHandlerConfig;
    }

    public HttpDataPublisher(String endPoint, String authToken) {

        setAuthToken(authToken);
        setEndPoint(endPoint);
    }

    public boolean publish(JSONObject data, String correlationID) {

        String localEndPoint = endPoint;
        JSONObject serverRequestPayload = (JSONObject) data.get(SecurityHandlerConstants.SERVER_PAYLOAD_KEY_NAME);
        String apiContext = (String) data.get(SecurityHandlerConstants.JSON_KEY_API_CONTEXT);
        String validationEndpoint = endPoint + "/" + apiContext + SecurityHandlerConstants.ALLOW_RULE;
        HttpPost postRequest = new HttpPost(validationEndpoint);
        postRequest.addHeader(SecurityHandlerConstants.AUTH_TOKEN_HEADER, authToken);
        postRequest.addHeader("Content-type", "application/json");

        if (log.isDebugEnabled()){
            log.debug("Request endpoint is " + validationEndpoint + " and request payload " + serverRequestPayload.toString());

        }

        CloseableHttpResponse response = null;
        int serverResponseCode;
        boolean serverResponse = securityHandlerConfig.getDefaultActionIfServerNotReachable();
        try {
            postRequest.setEntity(new StringEntity(serverRequestPayload.toString()));
            long publishingStartTime = System.nanoTime();
            response = httpClient.execute(postRequest);
            long publishingEndTime = System.nanoTime();

            if (response != null) {
                serverResponseCode = response.getStatusLine().getStatusCode();
                switch (serverResponseCode) {
                    case SecurityHandlerConstants.SERVER_RESPONSE_BAD_REQUEST:
                        log.error("Incorrect JSON format sent for the server from the request " + correlationID);
                        break;
                    case SecurityHandlerConstants.SERVER_RESPONSE_SERVER_ERROR:
                        if (log.isDebugEnabled()) {
                            log.debug("OPA Server error code sent for the request " + correlationID);
                        }
                        break;
                    case SecurityHandlerConstants.SERVER_RESPONSE_CODE_SUCCESS:
                        HttpEntity entity = response.getEntity();
                        String responseString = EntityUtils.toString(entity, "UTF-8");
                        if (log.isDebugEnabled()) {
                            log.debug("OPA Server Response for for the request " + correlationID
                                    + " was " + responseString);
                        }
                        if (responseString.equals("{}")) {
                            //The policy for this API has not been created at the OPA server. Request will be sent to
                            // backend without validation
                            if (log.isDebugEnabled()) {
                                log.debug("OPA Policy was not defined for the API " + apiContext);
                            }
                            serverResponse = securityHandlerConfig.getDefaultActionIfPolicyNotFound();
                        } else {
                            JSONParser parser = new JSONParser();
                            try {
                                JSONObject responseObject = (JSONObject) parser.parse(responseString);
                                Object resultObject = responseObject.get("result");
                                if (resultObject != null) {
                                    serverResponse = JavaUtils.isTrueExplicitly(resultObject);
                                }
                            } catch (ParseException e) {
                                log.error("Parsing exception for response " + correlationID);
                            }
                        }
                        break;
                }

                if (log.isDebugEnabled()) {
                    log.debug("OPA Server connection time for the request " + correlationID + " in nano seconds is "
                            + (publishingEndTime - publishingStartTime));
                }
            } else {
                log.error("Null response returned from OPA server for the request " + correlationID);
            }
        } catch (Exception ex) {
            log.error("Error sending the HTTP Request with id " + correlationID, ex);
            securityHandlerConfig.getServerConfig().shiftEndpoint(localEndPoint);
            endPoint = securityHandlerConfig.getServerConfig().getEndPoint();
        } finally {
            if (response != null) {
                try {
                    response.close();
                } catch (IOException e) {
                    log.error("Error when closing the response of the request id " + correlationID, e);
                }
            }
        }
        return serverResponse;
    }

    private void setAuthToken(String authToken) {

        this.authToken = authToken;
    }

    private void setEndPoint(String endPoint) {

        this.endPoint = endPoint;
    }

    public CloseableHttpClient getHttpClient() {

        return httpClient;
    }

    public void setHttpClient(CloseableHttpClient httpClient) {

        this.httpClient = httpClient;
    }

}

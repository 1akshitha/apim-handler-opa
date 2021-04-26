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

package org.wso2.carbon.apimgt.securityenforcer.opa;

import com.google.gson.Gson;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
import org.apache.openjpa.persistence.jest.JSON;
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.AbstractHandler;
import org.apache.synapse.rest.RESTConstants;
import org.apache.synapse.transport.passthru.PassThroughConstants;
import org.apache.synapse.transport.passthru.util.RelayUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.gateway.handlers.Utils;
import org.wso2.carbon.apimgt.gateway.handlers.security.AuthenticationContext;
import org.wso2.carbon.apimgt.securityenforcer.opa.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityException;
import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityHandlerConstants;
import org.wso2.carbon.apimgt.securityenforcer.opa.utils.SecurityUtils;

import java.util.Date;
import java.util.TreeMap;

/**
 * This class is Handling the OPA Security analysis. This class will use inside each API as securityenforcer.
 * It will fetch some of meta data from incoming message and send them to OPA Server.
 */
public class OPASecurityHandler extends AbstractHandler {

    private static final Log log = LogFactory.getLog(OPASecurityHandler.class);

    public OPASecurityHandler() {

        log.debug("OPA Security Handler initialized");
    }

    /**
     * This method will handle the request. For every request gateway receives, this is method will invoke first for
     * this handler
     */
    @Override
    public boolean handleRequest(MessageContext messageContext) {

        if (ServiceReferenceHolder.getInstance().getSecurityHandlerConfig().isPolicyEnforcementEnabled()) {
            long handleRequestStartTime = System.nanoTime();
            String correlationID = SecurityUtils.getAndSetCorrelationID(messageContext);
            try {
                if (authenticate(messageContext, correlationID)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Handle Request Time for the request " + correlationID + " is "
                                + (System.nanoTime() - handleRequestStartTime) + " Nano seconds");
                    }
                    SecurityUtils.updateLatency(System.nanoTime() - handleRequestStartTime, messageContext);
                }
            } catch (SecurityException e) {
                if (log.isDebugEnabled()) {
                    long difference = System.nanoTime() - handleRequestStartTime;
                    String messageDetails = logMessageDetails(messageContext);
                    log.debug("Request " + correlationID + " failed. " + messageDetails + ", elapsedTimeInNano "
                            + difference);
                }
                handleAuthFailure(messageContext, e);
            } finally {
                SecurityUtils.updateLatency(System.nanoTime() - handleRequestStartTime, messageContext);
            }
        }
        return true;
    }

    /**
     * This method will handle the response.
     */
    @Override
    public boolean handleResponse(MessageContext messageContext) {

        return true;
    }

    /**
     * This method will return true if the request is authorized.
     */
    private boolean authenticate(MessageContext messageContext, String correlationID)
            throws SecurityException {

        JSONObject requestMetaData = extractRequestMetadata(messageContext);
        return ServiceReferenceHolder.getInstance().getRequestPublisher()
                .verifyRequest(requestMetaData, correlationID);
    }

    /**
     * This method will extract the required meta data from the synapse context.
     */
    JSONObject extractRequestMetadata(MessageContext messageContext) throws SecurityException {

        String correlationID = SecurityUtils.getAndSetCorrelationID(messageContext);

        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();
        TreeMap<String, String> transportHeadersMap = (TreeMap<String, String>) axis2MessageContext
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        JSONObject transportHeaders = SecurityUtils.getTransportHeaders(transportHeadersMap, correlationID);

        String requestOriginIP = SecurityUtils.getIp(axis2MessageContext);
        int requestOriginPort = SecurityHandlerConstants.DUMMY_REQUEST_PORT;
        String requestMethod = (String) axis2MessageContext.getProperty(SecurityHandlerConstants.HTTP_METHOD_STRING);
        String requestPath = (String) axis2MessageContext.getProperty(SecurityHandlerConstants.API_BASEPATH_STRING);
        String apiContext = SecurityUtils.getContext(requestPath);
        String requestHttpVersion = SecurityUtils.getHttpVersion(axis2MessageContext);

        JSONObject opaPayload =
                createRequestPayloadJson(apiContext, requestMethod, requestPath, requestHttpVersion, requestOriginIP,
                        requestOriginPort, transportHeaders);

        String authHeader = transportHeadersMap.get(SecurityHandlerConstants.AUTHORIZATION_HEADER_NAME);
        AuthenticationContext authContext = (AuthenticationContext) messageContext.getProperty("__API_AUTH_CONTEXT");
        if (authContext != null) {
            //OAuth or APIKey header may not be included in the transport headers after the Authentication handler.
            //Therefore getApiKey method from authContext is used. This will return Oauth Token or API key and if it's
            //unauthenticated, ip is returned.
            String APIKey = authContext.getApiKey();
            if (!SecurityHandlerConstants.UNAUTHENTICATED_TIER.equals(authContext.getTier()) && authContext != null) {
                if (APIKey != null && authHeader == null) {
                    authHeader = "Bearer " + APIKey;
                    transportHeaders.put(SecurityHandlerConstants.AUTHORIZATION_HEADER_NAME, authHeader);
                }
            }
            String authContextSting = new Gson().toJson(authContext);
            JSONParser parser = new JSONParser();
            JSONObject authContextJson;
            try {
                authContextJson = (JSONObject) parser.parse(authContextSting);
                //User Info is added only if the request is Authenticated
                opaPayload.put(SecurityHandlerConstants.JSON_KEY_AUTH_CONTEXT, authContextJson);
            } catch (ParseException e) {
                log.error("Error occurred when parsing authContext String", e);
                opaPayload.put(SecurityHandlerConstants.JSON_KEY_AUTH_CONTEXT, authContextSting);
            }

        }
        String hashedToken = "";
        if (authHeader != null) {
            //This hashedToken is used as the key of cookie cache
            hashedToken = DigestUtils.md5Hex(authHeader);
        }

        String cookie = SecurityUtils.getCookie(transportHeadersMap);
        String hashedCookie = "";
        if (cookie != null) {
            //This cookieHash is used as the key of cookie cache
            hashedCookie = DigestUtils.md5Hex(cookie);
        }

        JSONObject requestPayload = new JSONObject();
        JSONObject inputObject = new JSONObject();
        inputObject.put(SecurityHandlerConstants.INPUT_KEY_NAME, opaPayload); // request payload is structured to wrap from input key
        requestPayload.put(SecurityHandlerConstants.SERVER_PAYLOAD_KEY_NAME, inputObject);
        requestPayload.put(SecurityHandlerConstants.JSON_KEY_API_CONTEXT, apiContext);
        requestPayload.put(SecurityHandlerConstants.COOKIE_KEY_NAME, hashedCookie);
        requestPayload.put(SecurityHandlerConstants.IP_KEY_NAME, requestOriginIP);
        requestPayload.put(SecurityHandlerConstants.TOKEN_KEY_NAME, hashedToken);
        return requestPayload;
    }

    /**
     * This method will format the extracted details to a given json format
     */
    private JSONObject createRequestPayloadJson(String apiContext, String requestMethod, String requestPath,
                                                String requestHttpVersion,
                                                String requestOriginIP, int requestOriginPort,
                                                JSONObject transportHeaders) {

        JSONObject requestBodyJson = new JSONObject();
        requestBodyJson.put(SecurityHandlerConstants.JSON_KEY_API_CONTEXT, apiContext);
        requestBodyJson.put(SecurityHandlerConstants.JSON_KEY_SOURCE_IP, requestOriginIP);
        requestBodyJson.put(SecurityHandlerConstants.JSON_KEY_SOURCE_PORT, requestOriginPort);
        requestBodyJson.put(SecurityHandlerConstants.JSON_KEY_METHOD, requestMethod);
        requestBodyJson.put(SecurityHandlerConstants.JSON_KEY_API_BASEPATH, requestPath);
        requestBodyJson.put(SecurityHandlerConstants.JSON_KEY_HTTP_VERSION, requestHttpVersion);
        requestBodyJson.put(SecurityHandlerConstants.JSON_KEY_HEADERS, transportHeaders);
        return requestBodyJson;
    }

    protected void handleAuthFailure(MessageContext messageContext, SecurityException e) {

        Mediator sequence = messageContext.getSequence("_auth_failure_handler_");
        // Invoke the custom error handler specified by the user
        if (sequence != null && !sequence.mediate(messageContext)) {
            // If needed user should be able to prevent the rest of the fault handling
            // logic from getting executed
            return;
        }

        org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();
        // This property need to be set to avoid sending the content in pass-through pipe (request message)
        // as the response.
        axis2MC.setProperty(PassThroughConstants.MESSAGE_BUILDER_INVOKED, Boolean.TRUE);
        try {
            RelayUtils.consumeAndDiscardMessage(axis2MC);
        } catch (AxisFault axisFault) {
            //In case of an error it is logged and the process is continued because we're setting a fault message
            // in the payload.
            log.error("Error occurred while consuming and discarding the message", axisFault);
        }
        axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, "application/soap+xml");
        int status;
        String errorMessage;
        if (e.getErrorCode() == SecurityException.HANDLER_ERROR) {
            status = HttpStatus.SC_INTERNAL_SERVER_ERROR;
            errorMessage = "Internal Sever Error";
        } else if (e.getErrorCode() == SecurityException.ACCESS_REVOKED) {
            status = HttpStatus.SC_FORBIDDEN;
            errorMessage = "Forbidden";
        } else if (e.getErrorCode() == SecurityException.CLIENT_REQUEST_ERROR) {
            status = HttpStatus.SC_BAD_REQUEST;
            errorMessage = "Bad Request";
        } else {
            status = HttpStatus.SC_UNAUTHORIZED;
            errorMessage = "Unauthorized";
        }

        messageContext.setProperty(SynapseConstants.ERROR_CODE, status);
        messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, errorMessage);
        messageContext.setProperty(SynapseConstants.ERROR_EXCEPTION, e);

        if (messageContext.isDoingPOX() || messageContext.isDoingGET()) {
            Utils.setFaultPayload(messageContext,
                    SecurityUtils.getFaultPayload(new SecurityException(status, errorMessage, e)));
        } else {
            Utils.setSOAPFault(messageContext, "Client", "Authentication Failure from AI Security Handler",
                    e.getMessage());
        }
        Utils.sendFault(messageContext, status);
    }

    private String logMessageDetails(MessageContext messageContext) {

        String applicationName = (String) messageContext.getProperty(SecurityHandlerConstants.APPLICATION_NAME);
        String endUserName = (String) messageContext.getProperty(SecurityHandlerConstants.END_USER_NAME);
        Date incomingReqTime = null;
        org.apache.axis2.context.MessageContext axisMC = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();
        String logMessage = "API call failed reason=OPA_authentication_failure";
        String logID = axisMC.getOptions().getMessageId();
        if (applicationName != null) {
            logMessage = logMessage + " belonging to appName=" + applicationName;
        }
        if (endUserName != null) {
            logMessage = logMessage + " userName=" + endUserName;
        }
        if (logID != null) {
            logMessage = logMessage + " transactionId=" + logID;
        }
        String userAgent = (String) ((TreeMap) axisMC
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS)).get("User-Agent");
        if (userAgent != null) {
            logMessage = logMessage + " with userAgent=" + userAgent;
        }
        String accessToken = (String) ((TreeMap) axisMC
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS))
                .get(SecurityHandlerConstants.AUTHORIZATION);
        if (accessToken != null) {
            logMessage = logMessage + " with accessToken=" + accessToken;
        }
        String requestURI = (String) messageContext.getProperty(RESTConstants.REST_FULL_REQUEST_PATH);
        if (requestURI != null) {
            logMessage = logMessage + " for requestURI=" + requestURI;
        }
        String requestReceivedTime = (String) ((Axis2MessageContext) messageContext).getAxis2MessageContext()
                .getProperty(SecurityHandlerConstants.REQUEST_RECEIVED_TIME);
        if (requestReceivedTime != null) {
            long reqIncomingTimestamp = Long.parseLong(requestReceivedTime);
            incomingReqTime = new Date(reqIncomingTimestamp);
            logMessage = logMessage + " at time=" + incomingReqTime;
        }

        String remoteIP = (String) axisMC.getProperty(org.apache.axis2.context.MessageContext.REMOTE_ADDR);
        if (remoteIP != null) {
            logMessage = logMessage + " from clientIP=" + remoteIP;
        }
        return logMessage;
    }

}


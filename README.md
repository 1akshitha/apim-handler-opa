# Introduction

WSO2 API Manager is a full lifecycle API Management solution which has an API Gateway and a Microgateway.

This explains how WSO2 API Manager plans to integrate with PingIntelligence and expose APIs protected with
artificial intelligence (AI).

## WSO2 API Manager Extension with Open Policy Agent

### What is Open Policy Agent?
The Open Policy Agent (OPA, pronounced “oh-pa”) is an open source, general-purpose policy engine that unifies policy 
enforcement across the stack. OPA provides a high-level declarative language that lets you specify policy as code and 
simple APIs to offload policy decision-making from your software. You can use OPA to enforce policies in microservices, 
Kubernetes, CI/CD pipelines, API gateways, and more.

### How does integration happen?
The WSO2 API Manager extension for Open Policy Agent uses a new custom handler (OPA Security Handler) when working with 
the WSO2 API Gateway data flow. After this handler receives a request from a client, a http call is sent to OPA server 
with the client request metadata. The OPA server responds after validating the metadata with the defined policies.

If the response of OPA server is {"result" : true} , the OPA Security Handler forwards the request and if the response 
is {"result" : false}, it blocks the request.




### Quick Start Guide

To use this extension with WSO2 API Manager 3.0.0 or newer versions, see [Quick Start Guide New](https://github.com/1akshitha/apim-handler-opa/blob/master/QUICK_START_GUIDE_NEW.md).

WSO2 API Manager 2.6.0 or older versions, see [Quick Start Guide Old](https://github.com/1akshitha/apim-handler-opa/blob/master/QUICK_START_GUIDE_OLD.md).

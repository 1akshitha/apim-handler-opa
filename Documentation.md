# WSO2 API Manager extension with Open Policy Agent

## WSO2 API manager

WSO2 API Manager is a complete platform for building, integrating, and exposing your digital services as managed APIs in the cloud, on-premise, and hybrid architectures to drive your digital transformation strategy.

It allows API developers to design, publish, and manage the lifecycle of APIs and API product managers to create API products from one or more APIs.


## Open Policy Agent

The Open Policy Agent (OPA) is an open source, general-purpose policy engine that unifies policy enforcement across the stack. 
OPA provides a high-level declarative language that lets users to specify policy as code and simple APIs to offload policy decision-making from the software. 
Users can use OPA to enforce policies in microservices, Kubernetes, CI/CD pipelines, API gateways, and more.

## How this happens

To achieve advanced and customized policy use cases, we can easily use OPA policy engine with WSO2 API manager. Data flow will be as follows.    

![alt text](https://raw.githubusercontent.com/1akshitha/apim-handler-opa/master/images/OPA-integration.png)

This integration consists of a new custom handler (OPA Security Handler) when working with the WSO2 API Gateway data flow. After this handler receives a request from a client, an http/https request is sent to the OPA engine with the client request metadata.
This meta data contains all the relevant information regarding the request and policy makers can use these information to define their polices.

The OPA engine responds after validating the input against the written rego policy and provided additional data for the policy.

If the response will be either true or false and if it responds with true, the OPA Security Handler will forward the request and if the response is false, it blocks the request.


## Integration

#### Prerequisites

- **Install Java 7, 8 or 11.**
(http://www.oracle.com/technetwork/java/javase/downloads/)

- **Install Apache Maven 3.x.x**
 (https://maven.apache.org/download.cgi#)

- **Install the latest WSO2 API Manager**.
(https://wso2.com/api-management/)

    Installing WSO2 is very fast and easy. Before you begin, be sure you have met the installation prerequisites, 
    and then follow the [installation instructions for your platform](https://apim.docs.wso2.com/en/latest/install-and-setup/install/installing-the-product/installing-the-product/).

- **Download the [OPA server](https://www.openpolicyagent.org/docs/latest/#running-opa) and run as a server**
```
./opa run --server
```

## Deploy WSO2 Extension with Open Policy Agent

**IMPORTANT**

Following configurations are for WSO2 Api Manager 3.0.0 or newer versions. For older versions, please refer
 [Developer Guide.](https://github.com/1akshitha/apim-handler-opa/blob/master/QUICK_START_GUIDE_OLD.md)


### For System Admin

1. Download the extension and navigate to the **apim-handler-opa** directory. Update the pom.xml with corresponding dependency versions and run the following Maven command.
   ```
    mvn clean install
     ```
    org.wso2.carbon.apimgt.securityenforcer.opa-\<version>.jar file can be found in **apim-handler-opa/target** directory.

    Use the following table to update pom.xml with the corresponding dependency versions for API manager.

     | Dependency                |  APIM 4.0.0  |  APIM 3.2.0 |  APIM 3.1.0 |  APIM 3.0.0 |  
     | ------------------------- |:------------:|:-----------:|:-----------:|:-----------:|  
     | org.wso2.carbon.apimgt    |    9.0.174   |    6.7.206   |    6.6.163 |    6.5.349  |

2. Add the JAR file of the extension to the **<APIM_HOME>/repository/components/dropins** directory.
   You can find the org.wso2.carbon.apimgt.securityenforcer.opa-\<version>.jar file in the **apim-handler-opa/target** directory.

3. Add the bare minimum configurations to the *deployment.toml* file, which can be found in the
**<APIM_HOME>/repository/conf** directory.

   ```
    [apim.opa_security]
    operation_mode = "sync"
    server_endpoint = "http://localhost:8181/v1/data"
   ```
   
4. To engage the handler to APIs, you need to update the **<APIM_HOME>/repository/resources/api_templates/velocity_template.xml** file.
   Add the handler class as follows inside the *\<handlers xmlns="http://ws.apache.org/ns/synapse">* just after the foreach loop.
   ```
   <handler class="org.wso2.carbon.apimgt.securityenforcer.opa.OPASecurityHandler"/>
   ```
   In the default velocity_template.xml file, it should be as follows.
     ```
   <handlers xmlns="http://ws.apache.org/ns/synapse">
   #foreach($handler in $handlers)
   <handler xmlns="http://ws.apache.org/ns/synapse" class="$handler.className">
       #if($handler.hasProperties())
       #set ($map = $handler.getProperties() )
       #foreach($property in $map.entrySet())
       <property name="$!property.key" value="$!property.value"/>
       #end
       #end
   </handler>
   #end
   <handler class="org.wso2.carbon.apimgt.securityenforcer.opa.OPASecurityHandler"/>
   </handlers>
     ```

5. Add the j2 mapping found in the apim-handler-opa/api-manager.xml.j2 to the 
**<API_HOME>/repository/resources/conf/templates/repository/conf/api-manager.xml.j2**. This will map all the configs 
added the deployment.toml.

### For the API Publisher

Every API Published after following the above steps will be eligible for OPA security. Every API request received 
to the gateway will be blocked (if sync mode is used), extract the meta information and sent to the OPA server. If there
is a Rego policy for the API at the OPA server, the meta data will be validated against the policy. Result of the policy
will be sent back to the gateway and based on the result, handler will allow or block the API request.

#### Meta info published to OPA server

Below is an example input.json published to the OPA server for the PizzaShackAPI's GET /menu resource invocation.

```
{
    "input": {
      "path": "/pizzashack/1.0.0/menu",
      "headers": {
        "Origin": "https://localhost:9443",
        "Connection": "keep-alive",
        "Referer": "https://localhost:9443/",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Site": "same-site",
        "Host": "localhost:8243",
        "Accept-Encoding": "gzip, deflate, br",
        "accept": "application/json",
        "Sec-Fetch-Mode": "cors",
        "Authorization": "Bearer eyJ4NXQiOiJNell4TW1Ga09HWXdNV0kwWldObU5EY3hOR1l3WW1NNFpUQTNNV0kyTkRBelpHUXpOR00wWkdSbE5qSmtPREZrWkRSaU9URmtNV0ZoTXpVMlpHVmxOZyIsImtpZCI6Ik16WXhNbUZrT0dZd01XSTBaV05tTkRjeE5HWXdZbU00WlRBM01XSTJOREF6WkdRek5HTTBaR1JsTmpKa09ERmtaRFJpT1RGa01XRmhNelUyWkdWbE5nX1JTMjU2IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJhZG1pbiIsImF1dCI6IkFQUExJQ0FUSU9OIiwiYXVkIjoia093VFFTZzNzd01lZjhjcGVVUkZYeXd0THNvYSIsIm5iZiI6MTYyMjQwNzE1MiwiYXpwIjoia093VFFTZzNzd01lZjhjcGVVUkZYeXd0THNvYSIsInNjb3BlIjoiZGVmYXVsdCIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsImV4cCI6MTYyMjQxMDc1MiwiaWF0IjoxNjIyNDA3MTUyLCJqdGkiOiI1MjRhZTc4MS1jZDc0LTQ2MGUtODMzYS03Yzk4MmRlMjFiMmEifQ.vJT5RroUl0zyD9eSxsmu9gIyQ0jZeRRb9_2UXwd_4XNkwu1A0LUu2pkUR37LP9u4hDyVV1Kwb37Ktp6rzPrnSyNDVGTdJpnFh9xdE0f6SkWeUpFnqmifcbq5jyoM1zozQ5J7mhqtFyahAmqTvHsdR2DnCQYAVUNlTNBEVoV3oYJLrvMsT_37ZKO5SPTRFT-JRyy-1Sz54dFz6x7DzNxNmysW_2NEw3URvCNtB0CNbs0H3VYQXk1T1ZVmmLW-_eDEIheduKjavUHihG-5mt2Mb-Rq_FOP78zQKqjfbwLkuPn7pIHWmyIPAABluPT49GISlZN_ti_a2SdMFVudH1Ziog",
        "activityid": "908d2c0a-e11c-4d6b-9dfb-dc1c67712de7",
        "sec-ch-ua": "\" Not;A Brand\";v=\"99\", \"Google Chrome\";v=\"91\", \"Chromium\";v=\"91\"",
        "sec-ch-ua-mobile": "?0",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8"
      },
      "method": "GET",
      "source_port": 8080,
      "context": "pizzashack",
      "auth_context": {
        "authenticated": true,
        "apiName": "PizzaShackAPI",
        "applicationUUID": "63cf4107-ff76-4fd5-a322-1fc13c9ce85d",
        "subscriber": "admin",
        "apiKey": "524ae781-cd74-460e-833a-7c982de21b2a",
        "stopOnQuotaReach": true,
        "issuer": "https://localhost:9443/oauth2/token",
        "isContentAwareTierPresent": false,
        "tier": "Unlimited",
        "subscriberTenantDomain": "carbon.super",
        "apiPublisher": "admin",
        "applicationTier": "Unlimited",
        "spikeArrestLimit": 0,
        "keyType": "PRODUCTION",
        "applicationId": "1",
        "consumerKey": "kOwTQSg3swMef8cpeURFXywtLsoa",
        "applicationName": "DefaultApplication",
        "username": "admin@carbon.super"
      },
      "http_version": "1.1",
      "source_ip": "127.0.0.1"
    }
  }
```

Policy writer can write a Rego Policy based on the above input.json.

**IMPORTANT**   
- Inorder to automate the policy validation, it is **mandatory** to use the API context(base path) as the policy name.
For an example, for PizzaShackAPI, we used pizzashack as the name of the Rego policy.

- Example Rego Policy: This policy will decode the Authorization header and verify whether the claim - sub is admin or not.
- It is mandatory to wrap all the policy validations to ```allow``` rule and validation should have a **binary** output.

```
package pizzashack

default allow = false

allow {

	claims.sub == "admin"
}

claims := payload {
	[_, payload, _] := io.jwt.decode(bearer_token)
}

bearer_token := t {
	v := input.headers.Authorization
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
}

```

- To publish this Rego policy, use the following curl.
```
curl -X PUT http://localhost:8181/v1/policies/pizzashack --data-binary @pizzashack.rego
```

- Handler will verify the allow rule of the policy as follows with the input.json.
```
curl -X PUT http://localhost:8181/v1/data/pizzashack/allow --data-binary @input.json
```

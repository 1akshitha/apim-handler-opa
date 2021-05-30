# WSO2 API Manager extension with Open Policy Agent
**This guide is for API manager versions of 2.x versions only. For 3.x and 4.0.0, please refer the [QUICK_START_GUID_NEW](https://github.com/1akshitha/apim-handler-opa/blob/master/QUICK_START_GUIDE_NEW.md)**.

#### Prerequisites

- **Install Java 7, 8 or 11.**
(http://www.oracle.com/technetwork/java/javase/downloads/)

- **Install Apache Maven 3.x.x**
 (https://maven.apache.org/download.cgi#)

- **Install relevant WSO2 API Manager version**.
(https://wso2.com/api-management/previous-releases/)

    Installing WSO2 is very fast and easy. Before you begin, be sure you have met the installation prerequisites, 
    and then follow the [installation instructions for your platform](https://docs.wso2.com/display/AM260/Installation+Prerequisites/).

- **Download the [OPA server](https://www.openpolicyagent.org/docs/latest/#running-opa) and run as a server**
```
./opa run --server
```

## Deploy WSO2 Extension with Open Policy Agent

**IMPORTANT**

Following configurations are for WSO2 Api Manager 2.x versions.


### For System Admin

1. Download the extension and navigate to the **apim-handler-opa** directory. Update the pom.xml with corresponding dependency versions and run the following Maven command.
   ```
    mvn clean install
     ```
    org.wso2.carbon.apimgt.securityenforcer.opa-\<version>.jar file can be found in **apim-handler-opa/target** directory.

    Use the following table to update pom.xml with the corresponding dependency versions for API manager.

     | Dependency                |  APIM 2.6.0   |  APIM 2.5.0   |  APIM 2.2.0   |  APIM 2.1.0   |
     | ------------------------- | :-----------: | :-----------: | :-----------: | :-----------: |
     | org.wso2.carbon.apimgt    |    6.4.50     |    6.3.95     |    6.2.201    |    6.1.66     |

2. Add the JAR file of the extension to the **<APIM_HOME>/repository/components/dropins** directory.
   You can find the org.wso2.carbon.apimgt.securityenforcer.opa-\<version>.jar file in the **apim-handler-opa/target** directory.

3. Add the bare minimum configurations to the **<APIM_HOME>/repository/conf/api-manager.xml** file within the <APIManager> tag, which can be found in the
**<APIM_HOME>/repository/conf** directory.

```
    <OPASecurityHandler>
        <OperationMode>sync</OperationMode>
        <OPAServer>
            <EndPoint>http://localhost/8081/v1/data</EndPoint>
        </OPAServer>
    </OPASecurityHandler>
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

- It is mandatory to wrap all the policy validations to ```allow``` rule and validation should have a **binary** output.
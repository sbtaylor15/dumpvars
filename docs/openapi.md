---
title: ortelius-ms-dep-pkg-cud v10.0.0
language_tabs:
  - shell: Shell
  - http: HTTP
  - javascript: JavaScript
  - ruby: Ruby
  - python: Python
  - php: PHP
  - java: Java
  - go: Go
toc_footers: []
includes: []
search: true
highlight_theme: darkula
headingLevel: 2

---

<!-- Generator: Widdershins v4.0.1 -->

<h1 id="ortelius-ms-dep-pkg-cud">ortelius-ms-dep-pkg-cud v10.0.0</h1>

> Scroll down for code samples, example requests and responses. Select a language for code samples from the tabs above or the mobile navigation menu.

RestAPI endpoint for retrieving SBOM data to a component

Base URLs:

* <a href="http://localhost:5004">http://localhost:5004</a>

Email: <a href="mailto:support@ortelius.io">Ortelius Open Source Project</a> Web: <a href="https://github.com/ortelius/ortelius/issues">Ortelius Open Source Project</a> 
License: <a href="https://www.apache.org/licenses/LICENSE-2.0.html">Apache 2.0</a>

<h1 id="ortelius-ms-dep-pkg-cud-health">health</h1>

health check end point

## health_health_get

<a id="opIdhealth_health_get"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:5004/health \
  -H 'Accept: application/json'

```

```http
GET http://localhost:5004/health HTTP/1.1
Host: localhost:5004
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json'
};

fetch('http://localhost:5004/health',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json'
}

result = RestClient.get 'http://localhost:5004/health',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json'
}

r = requests.get('http://localhost:5004/health', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:5004/health', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:5004/health");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:5004/health", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /health`

*Health*

This health check end point used by Kubernetes

> Example responses

> 200 Response

```json
{
  "status": "",
  "service_name": ""
}
```

<h3 id="health_health_get-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Successful Response|[StatusMsg](#schemastatusmsg)|

<aside class="success">
This operation does not require authentication
</aside>

<h1 id="ortelius-ms-dep-pkg-cud-deppkg">deppkg</h1>

Retrieve Package Dependencies end point

## get_comp_pkg_deps_msapi_deppkg_get

<a id="opIdget_comp_pkg_deps_msapi_deppkg_get"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://localhost:5004/msapi/deppkg \
  -H 'Accept: application/json'

```

```http
GET http://localhost:5004/msapi/deppkg HTTP/1.1
Host: localhost:5004
Accept: application/json

```

```javascript

const headers = {
  'Accept':'application/json'
};

fetch('http://localhost:5004/msapi/deppkg',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```

```ruby
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json'
}

result = RestClient.get 'http://localhost:5004/msapi/deppkg',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json'
}

r = requests.get('http://localhost:5004/msapi/deppkg', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://localhost:5004/msapi/deppkg', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("http://localhost:5004/msapi/deppkg");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "Accept": []string{"application/json"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://localhost:5004/msapi/deppkg", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /msapi/deppkg`

*Get Comp Pkg Deps*

This is the end point used to retrieve the component's SBOM (package dependencies)

<h3 id="get_comp_pkg_deps_msapi_deppkg_get-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|compid|query|any|false|none|
|appid|query|any|false|none|
|deptype|query|string|false|none|

> Example responses

> 200 Response

```json
{
  "data": []
}
```

<h3 id="get_comp_pkg_deps_msapi_deppkg_get-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|Successful Response|[DepPkgs](#schemadeppkgs)|
|422|[Unprocessable Entity](https://tools.ietf.org/html/rfc2518#section-10.3)|Validation Error|[HTTPValidationError](#schemahttpvalidationerror)|

<aside class="success">
This operation does not require authentication
</aside>

# Schemas

<h2 id="tocS_DepPkg">DepPkg</h2>
<!-- backwards compatibility -->
<a id="schemadeppkg"></a>
<a id="schema_DepPkg"></a>
<a id="tocSdeppkg"></a>
<a id="tocsdeppkg"></a>

```json
{
  "packagename": "",
  "packageversion": "",
  "pkgtype": "",
  "name": "",
  "url": "",
  "summary": "",
  "fullcompname": "",
  "risklevel": ""
}

```

DepPkg

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|packagename|string|false|none|none|
|packageversion|string|false|none|none|
|pkgtype|string|false|none|none|
|name|string|false|none|none|
|url|string|false|none|none|
|summary|string|false|none|none|
|fullcompname|string|false|none|none|
|risklevel|string|false|none|none|

<h2 id="tocS_DepPkgs">DepPkgs</h2>
<!-- backwards compatibility -->
<a id="schemadeppkgs"></a>
<a id="schema_DepPkgs"></a>
<a id="tocSdeppkgs"></a>
<a id="tocsdeppkgs"></a>

```json
{
  "data": []
}

```

DepPkgs

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|data|[[DepPkg](#schemadeppkg)]|false|none|none|

<h2 id="tocS_HTTPValidationError">HTTPValidationError</h2>
<!-- backwards compatibility -->
<a id="schemahttpvalidationerror"></a>
<a id="schema_HTTPValidationError"></a>
<a id="tocShttpvalidationerror"></a>
<a id="tocshttpvalidationerror"></a>

```json
{
  "detail": [
    {
      "loc": [
        "string"
      ],
      "msg": "string",
      "type": "string"
    }
  ]
}

```

HTTPValidationError

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|detail|[[ValidationError](#schemavalidationerror)]|false|none|none|

<h2 id="tocS_StatusMsg">StatusMsg</h2>
<!-- backwards compatibility -->
<a id="schemastatusmsg"></a>
<a id="schema_StatusMsg"></a>
<a id="tocSstatusmsg"></a>
<a id="tocsstatusmsg"></a>

```json
{
  "status": "",
  "service_name": ""
}

```

StatusMsg

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|status|string|false|none|none|
|service_name|string|false|none|none|

<h2 id="tocS_ValidationError">ValidationError</h2>
<!-- backwards compatibility -->
<a id="schemavalidationerror"></a>
<a id="schema_ValidationError"></a>
<a id="tocSvalidationerror"></a>
<a id="tocsvalidationerror"></a>

```json
{
  "loc": [
    "string"
  ],
  "msg": "string",
  "type": "string"
}

```

ValidationError

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|loc|[anyOf]|true|none|none|

anyOf

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|» *anonymous*|string|false|none|none|

or

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|» *anonymous*|integer|false|none|none|

continued

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|msg|string|true|none|none|
|type|string|true|none|none|


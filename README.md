# Ping/ForgeRock Advanced Identity Cloud (AIC) Python Service Account Module: AICServiceAccount

## Overview

The `AICServiceAccount` module provides a class for managing and authenticating service accounts with AIC using JWT (JSON Web Token) and OAuth2. The module includes functionality to handle access tokens, ensuring they are refreshed before expiration.

## Features

- Support for various Ping/ForgeRock Identity Cloud scopes.
- Automated JWT generation for OAuth2 token requests.
- Handling of access token refresh and expiry.
- Logging for debugging and error tracking.

## Installation

Ensure you have the required dependencies installed. You can install them using `pip`:

```bash
pip install requests jwcrypto
```

## Usage

### Importing the Module

```python
from aic_service_account import AICServiceAccount
```

### Creating a Service Account Instance

You can create a `AICServiceAccount` instance by providing the necessary parameters.

```python
fqdn = "your-forgerock-domain.com"
scopes = "fr:am:* fr:idm:*"
service_account_id = "your-service-account-id"
service_private_key_path = "/path/to/your/private_key.json"

service_account = AICServiceAccount(
    fqdn=fqdn,
    scopes=scopes,
    service_account_id=service_account_id,
    service_private_key_path=service_private_key_path
)
```

Alternatively, you can provide the private key as a JSON string:

```python
service_private_key = '{"kty":"RSA","n":"...","e":"...","d":"...","p":"...","q":"...","dp":"...","dq":"...","qi":"..."}'

service_account = AICServiceAccount(
    fqdn=fqdn,
    scopes=scopes,
    service_account_id=service_account_id,
    service_private_key=service_private_key
)
```

### Getting an Access Token

To obtain an access token, use the `get_access_token` method:

```python
access_token = service_account.get_access_token()
print(access_token)
```

This method will automatically refresh the token if it has expired or is close to expiring.

## Available Scopes

The following scopes are supported by the `ServiceAccount` module:

- `fr:am:*`: All Access Management APIs
- `fr:autoaccess:*`: All Auto Access APIs
- `fr:idc:advanced-gateway:*`: All WAF APIs
- `fr:idc:advanced-gateway:read`: Read WAF configurations
- `fr:idc:advanced-gateway:write`: Write WAF configurations
- `fr:idc:analytics:*`: All Analytics APIs
- `fr:idc:certificate:*`: All TLS certificate APIs
- `fr:idc:certificate:read`: Read TLS certificates
- `fr:idc:content-security-policy:*`: All content security policy APIs
- `fr:idc:cookie-domain:*`: All cookie domain APIs
- `fr:idc:custom-domain:*`: All custom domain APIs
- `fr:idc:esv:*`: All ESV APIs
- `fr:idc:esv:read`: Read ESVs, excluding values of secrets
- `fr:idc:esv:update`: Create, modify, and delete ESVs
- `fr:idc:esv:restart`: Restart workloads that consume ESVs
- `fr:idc:promotion:*`: All configuration promotion APIs
- `fr:idc:release:*`: All product release APIs
- `fr:idc:sso-cookie:*`: All SSO cookie APIs
- `fr:idm:*`: All Identity Management APIs
- `fr:iga:*`: All Identity Governance APIs

## Error Handling

The module includes logging for error handling and debugging. Ensure logging is configured in your application to capture these logs:

```python
import logging

logging.basicConfig(level=logging.DEBUG)
```

## Example

```python
import logging
from aic_service_account import AICServiceAccount

logging.basicConfig(level=logging.DEBUG)

fqdn = "your-forgerock-domain.com"
scopes = "fr:am:* fr:idm:*"
service_account_id = "your-service-account-id"
service_private_key_path = "/path/to/your/test_privateKey.jwk"

service_account = AICServiceAccount(
    fqdn=fqdn,
    scopes=scopes,
    service_account_id=service_account_id,
    service_private_key_path=service_private_key_path
)

try:
    access_token = service_account.get_access_token()
    print("Access Token:", access_token)
except Exception as e:
    logging.error(f"An error occurred: {e}")
```

This example demonstrates creating a `AICServiceAccount` instance, configuring logging, and retrieving an access token.

---

This README provides a comprehensive guide on how to use the `AICServiceAccount` module, ensuring you can authenticate and manage service accounts effectively within AIC.
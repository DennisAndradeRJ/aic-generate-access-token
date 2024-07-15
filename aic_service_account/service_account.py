import base64
import os
import requests
import logging
from datetime import datetime, timedelta
from jwcrypto import jwk, jwt
from typing import Optional, Union

# Available scopes:
# fr:am:*
# All Access Management APIs
#
# fr:autoaccess:*
# All Auto Access APIs
#
# fr:idc:advanced-gateway:*
# All WAF APIs
#
# fr:idc:advanced-gateway:read
# Read WAF configurations
#
# fr:idc:advanced-gateway:write
# Write WAF configurations
#
# fr:idc:analytics:*
# All Analytics APIs
#
# fr:idc:certificate:*
# All TLS certificate APIs
#
# fr:idc:certificate:read
# Read TLS certificates
#
# fr:idc:content-security-policy:*
# All content security policy APIs
#
# fr:idc:cookie-domain:*
# All cookie domain APIs
#
# fr:idc:custom-domain:*
# All custom domain APIs
#
# fr:idc:esv:*
# All ESV APIs
#
# fr:idc:esv:read
# Read ESVs, excluding values of secrets
#
# fr:idc:esv:update
# Create, modify, and delete ESVs
#
# fr:idc:esv:restart
# Restart workloads that consume ESVs
#
# fr:idc:promotion:*
# All configuration promotion APIs
#
# fr:idc:release:*
# All product release APIs
#
# fr:idc:sso-cookie:*
# All SSO cookie APIs
#
# fr:idm:*
# All Identity Management APIs
#
# fr:iga:*
# All Identity Governance APIs

logger = logging.getLogger(__name__)

TOKEN_ENDPOINT = '/am/oauth2/access_token'
JWT_SIGNING_ALGORITHM = 'RS256'


class AICServiceAccount:
    """
    A class to represent a service account for Ping/ForgeRack AIC (Authentication and Identity Control).

    Attributes:
        available_scopes (set): A set of all AIC available scopes.
        fqdn (str): Fully Qualified Domain Name.
        token_ep_url (str): Token endpoint URL.
        aud (str): Audience for the JWT.
        service_account_id (str): ID of the service account.
        token_expiry_buffer (int): Buffer time in seconds for token expiry.
        access_token (str): Access token.
        access_token_expiry (datetime): Expiry time of the access token.
        scopes (str): Scopes for the service account.
        service_private_key (jwk.JWK): Private key for the service account.
    """

    available_scopes = {
        "fr:am:*",
        "fr:autoaccess:*",
        "fr:idc:advanced-gateway:*",
        "fr:idc:advanced-gateway:read",
        "fr:idc:advanced-gateway:write",
        "fr:idc:analytics:*",
        "fr:idc:certificate:*",
        "fr:idc:certificate:read",
        "fr:idc:content-security-policy:*",
        "fr:idc:cookie-domain:*",
        "fr:idc:custom-domain:*",
        "fr:idc:esv:*",
        "fr:idc:esv:read",
        "fr:idc:esv:update",
        "fr:idc:esv:restart",
        "fr:idc:promotion:*",
        "fr:idc:release:*",
        "fr:idc:sso-cookie:*",
        "fr:idm:*",
        "fr:iga:*",
    }

    def __init__(self, fqdn: str, scopes: str, service_account_id: str,
                 service_private_key: Optional[Union[str, dict]] = None,
                 service_private_key_path: Optional[str] = None, token_expiry_buffer: int = 180):
        """
        Constructs all the necessary attributes for the service account object.

        Args:
            fqdn (str): Fully Qualified Domain Name.
            scopes (str): Scopes for the service account.
            service_account_id (str): ID of the service account.
            service_private_key (Optional[Union[str, dict]]): Private key as JSON string or dict.
            service_private_key_path (Optional[str]): Path to the service account private key file.
            token_expiry_buffer (int): Buffer time in seconds for token expiry.
        """

        self.fqdn = fqdn if fqdn.startswith('http') else f'https://{fqdn}'
        self.token_ep_url = f"{self.fqdn}{TOKEN_ENDPOINT}"
        self.aud = f"{self.fqdn}{TOKEN_ENDPOINT}"
        self.service_account_id = service_account_id
        self.token_expiry_buffer = token_expiry_buffer  # Time in seconds to refresh before expiry
        self.access_token = None
        self.access_token_expiry = None
        self.scopes = scopes

        if service_private_key_path:
            self._set_private_key(service_private_key_path)
        elif service_private_key:
            self.service_private_key = jwk.JWK.from_json(service_private_key)
        else:
            logging.error("Either service_private_key or service_private_key_path must be provided")
            raise ValueError("Either service_private_key or service_private_key_path must be provided")

    def _set_private_key(self, service_private_key_path: str):
        try:
            with open(service_private_key_path, 'r') as f:
                self.service_private_key = jwk.JWK.from_json(f.read())
        except FileNotFoundError:
            logging.error(f"Private key file not found: {service_private_key_path}")
            raise FileNotFoundError(f"Private key file not found: {service_private_key_path}")
        except Exception as e:
            logging.error(f"An error occurred while reading the private key: {e}")
            raise Exception(f"An error occurred while reading the private key: {e}")

    def _generate_jwt(self) -> str:
        exp = int(datetime.timestamp(datetime.now())) + 180
        jti = base64.b64encode(os.urandom(16)).decode('utf-8')

        jwt_payload = {
            'jti': jti,
            'exp': exp,
            'iss': self.service_account_id,
            'sub': self.service_account_id,
            'aud': self.aud
        }
        logging.debug(f'JWT Payload: {jwt_payload}')
        token = jwt.JWT(header={'alg': JWT_SIGNING_ALGORITHM}, claims=jwt_payload)
        token.make_signed_token(self.service_private_key)
        return token.serialize()

    def is_token_expired(self) -> bool:
        if self.access_token_expiry is None:
            return True
        return (self.access_token_expiry - datetime.now()) < timedelta(seconds=self.token_expiry_buffer)

    def get_access_token(self) -> str:
        """
        Returns the access token. If the token is expired, refreshes it.

        Returns:
            str: Access token.
        """
        if self.is_token_expired():
            self.refresh_access_token()
        return self.access_token

    def refresh_access_token(self) -> str:
        jwt_assertion = self._generate_jwt()
        logging.debug(f'Scopes: {self._scopes}')

        request_payload = {
            'client_id': 'service-account',
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': jwt_assertion,
            'scope': self.scopes
        }

        response = requests.post(self.token_ep_url, data=request_payload)
        logging.debug(response.content)
        if response.status_code != 200:
            logging.error(f'Error getting access token, code: {response.status_code}, {response.text}')
            raise Exception(f'Error getting access token, code: {response.status_code}, {response.text}')

        response = response.json()
        if not response['access_token']:
            logging.error(f'Error getting access token: {response}')
            raise Exception('Access token not found in the response.')
        self.access_token = response['access_token']
        self.access_token_expiry = datetime.now() + timedelta(seconds=response['expires_in'])
        logging.debug(f'Access Token Expiry: {self.access_token_expiry}')
        return self.access_token

    @property
    def scopes(self) -> str:
        """
        Getter for scopes.

        Returns:
            str: Scopes as a space-separated string.
        """
        return ' '.join(self._scopes)

    # Validate AIC scopes
    @scopes.setter
    def scopes(self, scopes: str):
        """
        Setter for scopes. Validates the provided scopes against available scopes.

        Args:
            scopes (str): Scopes as a space-separated string.

        Raises:
            ValueError: If any of the provided scopes are invalid.
        """
        scopes_list = scopes.split(' ')
        invalid_scopes = [scope for scope in scopes_list if scope not in self.available_scopes]
        if invalid_scopes:
            logging.error(f'Invalid scopes: {", ".join(invalid_scopes)}')
            raise ValueError(f'Invalid scopes: {", ".join(invalid_scopes)}')
        self._scopes = scopes_list


# if __name__ == '__main__':
    # Example usage
    # logging.basicConfig(level=logging.INFO)
    # fqdn = 'https://example.com'
    # scopes = 'fr:am:* fr:idm:*'
    # svc_account_id = 'dbb1b0a5-3e2a-474e-97ff-40f9b81a97b3'
    # svc_private_key_path = '/path/to/privateKey.jwk'
    #
    # sc = ServiceAccount(fqdn, scopes, svc_account_id, service_private_key_path=svc_private_key_path)
    # access_token = sc.get_access_token()
    # logging.info(f'Access Token: {access_token}')
    # logging.info(f'Expires: {sc.access_token_expiry}')


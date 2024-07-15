import logging
from aic_service_account import AICServiceAccount

logging.basicConfig(level=logging.DEBUG)

fqdn = "openam-forgelab-dandrade.forgeblocks.com"
scopes = "fr:am:* fr:idm:*"
service_account_id = "250e107f-69ee-4702-a4b9-ccbf7a3806c7"
service_private_key_path = "/Users/dennis.andrade/Downloads/ServiceAccount-Valvoline_privateKey.jwk"

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
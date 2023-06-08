import os
import datetime
import base64
import json
from botocore.signers import CloudFrontSigner
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

def load_private_key(private_key_base64):
    return serialization.load_pem_private_key(
        base64.b64decode(private_key_base64),
        password=None,
        backend=default_backend()
    )

def rsa_signer(message, private_key):
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA1())

def cloudfront_policy(resource: str, expire_epoch_time: int):
    policy = {
        'Statement': [{
            'Resource': resource,
            'Condition': {
                'DateLessThan': {
                    'AWS:EpochTime': expire_epoch_time
                }
            }
        }]
    }
    return json.dumps(policy).replace(" ", "")
    
def url_base64_encode(data: bytes):
    return base64.b64encode(data).replace(b'+', b'-').replace(b'=', b'_').replace(b'/', b'~').decode('utf-8')

PRIVATE_KEY_BASE64 = os.environ['PRIVATE_KEY_BASE64']
PUBLIC_KEY_ID = os.environ['PUBLIC_KEY_ID']
DISTRIBUTION_URL = os.environ['DISTRIBUTION_URL']
EXPIRATION_SECONDS = int(os.environ['EXPIRATION_SECONDS'])

private_key = load_private_key(PRIVATE_KEY_BASE64)

expire_epoch_time = datetime.datetime.now() + datetime.timedelta(seconds=EXPIRATION_SECONDS)
expire_epoch_time = int(expire_epoch_time.timestamp())

# Create a signed url
policy = cloudfront_policy(DISTRIBUTION_URL, expire_epoch_time)
signature = rsa_signer(policy.encode('utf-8'), private_key)

signed_url = f"{DISTRIBUTION_URL}?Policy={url_base64_encode(policy.encode('utf-8'))}&Signature={url_base64_encode(signature)}&Key-Pair-Id={PUBLIC_KEY_ID}"

print(signed_url)

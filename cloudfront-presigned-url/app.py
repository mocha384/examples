import os
import datetime
import base64
from botocore.signers import CloudFrontSigner
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


def rsa_signer(message):
    private_key = serialization.load_pem_private_key(
        base64.b64decode(os.environ['PRIVATE_KEY_BASE64']),
        password=None,
        backend=default_backend()
    )
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA1())
    

key_id = os.environ['PUBLIC_KEY_ID']

url = os.environ['DISTRIBUTION_URL']
expiration = datetime.datetime.strptime(os.environ['EXPIRATION_DATE'], "%Y-%m-%d")

cloudfront_signer = CloudFrontSigner(key_id, rsa_signer)

#Create a signed url
signed_url = cloudfront_signer.generate_presigned_url(
    url,
    date_less_than=expiration
)

print(signed_url)

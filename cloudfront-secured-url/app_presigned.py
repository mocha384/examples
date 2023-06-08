import os
import datetime
import base64
from botocore.signers import CloudFrontSigner
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Load environment variables upfront
PRIVATE_KEY_BASE64 = os.environ['PRIVATE_KEY_BASE64']
PUBLIC_KEY_ID = os.environ['PUBLIC_KEY_ID']
DISTRIBUTION_URL = os.environ['DISTRIBUTION_URL']
EXPIRATION_DATE = datetime.datetime.strptime(os.environ['EXPIRATION_DATE'], "%Y-%m-%d")

def load_private_key(private_key_base64):
    """Function to load private key from base64 format"""
    return serialization.load_pem_private_key(
        base64.b64decode(private_key_base64),
        password=None,
        backend=default_backend()
    )

def rsa_signer(message):
    """Sign the message using RSA signing"""
    private_key = load_private_key(PRIVATE_KEY_BASE64)
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA1())

def generate_signed_url(key_id, distribution_url, expiration_date):
    """Function to generate a signed URL"""
    cloudfront_signer = CloudFrontSigner(key_id, rsa_signer)
    return cloudfront_signer.generate_presigned_url(
        distribution_url,
        date_less_than=expiration_date
    )

# Generate a signed url and print it
signed_url = generate_signed_url(PUBLIC_KEY_ID, DISTRIBUTION_URL, EXPIRATION_DATE)
print(signed_url)
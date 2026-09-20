import time
import base64
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt

app = Flask(__name__)

#Helper function to convert integers to base64url encoding
def int_to_base64(num):
    #Convert integers to bytes, then base64url encode without padding
    byte_length = (num.bit_length() + 7) // 8
    num_bytes = num.to_bytes(byte_length, 'big')
    return base64.urlsafe_b64encode(num_bytes).rstrip(b'=').decode('utf-8')

#Database to store RSA keys
KEYS_DB = {}

def generate_rsa_keys():
    #Generate a valid, unexpired key
    valid_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    KEYS_DB["valid_key"] = {
        "private_key" : valid_private_key,
        "kid" : "valid-kid-1",
        "expiry" : int(time.time()) + 3600  # Expires in 1 hour
    }

    #Generate an expired key
    expired_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    KEYS_DB["expired_key"] = {
        "private_key" : expired_private_key,
        "kid" : "expired-kid-1",
        "expiry" : int(time.time()) - 3600  # Expired 1 hour ago
    }

#Generate keys on startup
generate_rsa_keys()

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    #Serves unexpired public keys in JWKS format
    current_time = int(time.time())
    jwks_keys = []

    for key_name, key_data in KEYS_DB.items():
        #Only serve unexpired keys
        if key_data["expiry"] > current_time:
            public_key = key_data["private_key"].public_key()
            public_numbers = public_key.public_numbers()

            jwk = {
                "kty" : "RSA",
                "alg" : "RS256",
                "use" : "sig",
                "kid" : key_data["kid"],
                "n" : int_to_base64(public_numbers.n),
                "e" : int_to_base64(public_numbers.e)
            }
            jwks_keys.append(jwk)

        return jsonify({"keys" : jwks_keys})

@app.route('/auth', methods=['POST'])
def authenticate():
    #Returns a Jsigned JWT. If expired=true is passed, it uses the expired key.
    expired_param = request.args.get('expired')
    current_time = int(time.time())

    if expired_param == 'true':
        key_data = KEYS_DB["expired_key"]
        #Set token expiration to the past
        payload = {
            "sub" : "fake-user",
            "iat" : current_time - 7200,
            "exp" : current_time - 3600
        }
    else:
        key_data = KEYS_DB["valid_key"]
        #Set token expiration to the future
        payload = {
            "sub" : "fake-user",
            "iat" : current_time,
            "exp" : current_time + 3600
        }

    #Serialize private key to PEM format for PyJWT
    pem_private_key = key_data["private_key"].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    #Sign the JWT and include the 'kid' in the header
    token = jwt.encode(
        payload,
        pem_private_key,
        algorithm = "RS256",
        headers = {"kid" : key_data["kid"]} 
    )
    return token, 200, {'Content-Type' : 'text/plain'}

if __name__ == '__main__':
    app.run(port = 8080, debug = True)
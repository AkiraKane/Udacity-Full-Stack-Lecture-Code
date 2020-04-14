import jwt
import base64

# Init our data
payload = {
    "park": "madison square"
}

algo = "HS256" 
secret = "learning"

# Encode a JWT
encoded_jwt = jwt.encode(payload, secret, algorithm=algo)
print(encoded_jwt)

# Decode a JWT
decoded_jwt = jwt.decode(encoded_jwt, secret, verify=True)
print(decoded_jwt)

##########################################################################

## install a pip package in the current Jupyter kernel
import sys
!{sys.executable} -m pip install python-jose

import json
from jose import jwt
from urllib.request import urlopen

AUTH0_DOMAIN = "fsnd-akira.auth0.com"
ALGORITHMS = ["RS256"]
API_AUDIENCE = "image"

"""
AuthError Exception
A standardized way to communicate auth failure modes
"""
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjdmREt1ME1BbVZuMVVDVFJ5YXdKQyJ9.eyJpc3MiOiJodHRwczovL2ZzbmQtYWtpcmEuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDVlOTRiMjVhZDkwZTBhMGMxMGI0MGVhNiIsImF1ZCI6ImltYWdlIiwiaWF0IjoxNTg2ODAzMzE3LCJleHAiOjE1ODY4MTA1MTcsImF6cCI6IkhjMG1OTThFNDFoY2Y0VzJDVEh4UjVjNmxvVE5rQjNwIiwic2NvcGUiOiIifQ.b4gnHcqkYzzjFQa4Jdk-t7holDx2uB--4sOR0riXU1K0T3vyzdkiTqiqaqmTHRAOShzNwjBrCVDaSbTl2sLd_lnoWXt-KPo4WZ78A5kbGS3jBu2HppEtqCxxEe53y2K-NMl9VQXrGfkq6OGiCSAd5aH7ckJWUGBe8fNmhjMafBI8uctueMTSHxNaJuP3T5rv-kYbbkBsgCUxVF1kwL7E4otmwHWqcheST8RBtHlrvf1uR2raRCkLfBbqU8KAdeiMxhZkeLLFfFk1L7w-CBUJI7-NUKh8v3qhXRdiTSbCFMU_cy4EB4Rn22hwSUcC47cPGwE6KtCfHPUbgbdZfXaBwg"

# Auth Header
def verify_decode_jwt(token):
    # Get the public key from auth0
    jsonurl = urlopen(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())

    # Get the data in the header
    unverified_header = jwt.get_unverified_header(token)

    # Choose our key
    rsa_key = {}
    if "kid" not in unverified_header:
        raise AuthError({
        "code": "invalid_header",
        "description": "Authorization malformed"
    }, 401)

    for key in jwks['keys']:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }

    # Finally, verify
    if rsa_key:
        try:
            # Use the key to validate the JWT
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms = ALGORITHMS,
                audience = API_AUDIENCE,
                issuer = "https://" + AUTH0_DOMAIN + "/"
            )

            return payload
        
        except jwt.ExpiredSignatureError:
            raise AuthError({
            "code": "token_expired",
            "description": "Token expired"
        }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
            "code": invalid_claims,
            "description": "Incorrect claims. Please check the audience and issuer."
        }, 401)

        except Exception:
            raise AuthError({
            "code": "invalid_header",
            "description": "Unable to parse authentication token."
        }, 400)
            raise AuthError({
            "code": "invalid_header",
            "description": "Unable to find the appropriate key."
        }) 




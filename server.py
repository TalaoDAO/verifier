"""
MCP server to allow an AI agent to acces a wallet PID

"""
# --- Import required libraries ---
from flask import request,  jsonify, Response
import json
import uuid
from datetime import datetime
from urllib.parse import urlencode
import logging
import base64
from jwcrypto import jwk, jwt
import helpers
import x509_attestation
import redis
import io
import qrcode

# --- Configuration and Initialization ---
logging.basicConfig(level=logging.INFO)
red = redis.Redis(host='localhost', port=6379, db=0)


def init_app(app):
    # endpoints for OpenId customer application
    app.add_url_rule('/verifier/request_uri/<stream_id>', view_func=request_uri, methods=['GET', 'POST'])
    app.add_url_rule('/verifier/response_uri/<request_id>',  view_func=response_endpoint, methods=['POST'])
    return


# --- Generate a base64 QR code image from a URL ---
def generate_qr_base64(url: str) -> str:
    img = qrcode.make(url)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    base64_img = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{base64_img}"


# --- Load verifier-specific data from profile ---
def get_verifier_data(verifier_id: str) -> dict:
    try:
        f = open('verifier-profile.json', 'r')
        return json.loads(f.read())[verifier_id]
    except Exception:
        logging.warning("verifier does not exist")
        return


# --- Build JWT authorization request ---
def build_jwt_request(key, kid, authorization_request) -> str:
    if key:
        key = json.loads(key) if isinstance(key, str) else key
        signer_key = jwk.JWK(**key) 
        alg = helpers.alg(key)
    else:
        alg = "none"
    header = {
        'typ': "oauth-authz-req+jwt",
        'alg': alg,
    }
    client_id = authorization_request["client_id"]
    if authorization_request["client_id_scheme"] == "x509_san_dns":
        header['x5c'] = x509_attestation.build_x509_san_dns()
    elif authorization_request["client_id_scheme"] == "verifier_attestation":
        header['jwt'] = x509_attestation.build_verifier_attestation(client_id)
    elif authorization_request["client_id_scheme"] == "redirect_uri":
        pass
    else:  # DID by default
        header['kid'] = kid
    
    payload = {
        'iss': client_id,
        'exp': round(datetime.timestamp(datetime.now())) + 1000
    }
    payload |= authorization_request
    if key:
        _token = jwt.JWT(header=header, claims=payload, algs=[alg])
        _token.make_signed_token(signer_key)
        return _token.serialize()
    else:
        _token = base64.urlsafe_b64encode(json.dumps(header).encode()).decode()
        _token += '.'
        _token += base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        return _token


# --- Generate QR code URL and session data for PID verification ---
def get_qrcode(client_id, request_id, server):
    verifier_data = get_verifier_data(client_id)
    presentation_definition = verifier_data['presentation_definition']
    nonce = str(uuid.uuid1())

    authorization_request = {
        "response_type": "vp_token",
        "nonce": nonce,
        "response_uri": server + 'verifier/response_uri/' + request_id,
        "client_id_scheme": "did",
        "client_id": verifier_data['did'],
        "aud": 'https://self-issued.me/v2',
        "client_metadata": json.load(open("verifier_metadata.json", 'r')),
        "response_mode": 'direct_post',
        "presentation_definition": presentation_definition,
    }
    logging.info("authorization request = %s", json.dumps(authorization_request, indent=4))
        
    # manage request as jwt
    request_as_jwt = build_jwt_request(
        verifier_data['jwk'],
        verifier_data['verificationMethod'],
        authorization_request
    )
    payload = {
        "request_as_jwt": request_as_jwt,
        "nonce": nonce,
        "aud": verifier_data['did'],
        "state": request_id,
        "raw": verifier_data.get('raw')
    }
    red.setex(request_id, 1000, json.dumps(payload))
    authorization_request_displayed = { 
            "client_id":  verifier_data['did'],
            "request_uri": server + "verifier/request_uri/" + request_id 
        }
    qrcode_content = "openid-vc://" + '?' + urlencode(authorization_request_displayed)
    logging.info("QRcode = %s", qrcode_content)
    logging.info("authorization request = %s", authorization_request_displayed)
    return qrcode_content



def initiate_oidc4vp_request(session_id, server):
    request_id = str(uuid.uuid4())
    authorization_request = get_qrcode("any", request_id, server)
    red.setex(request_id + "_MCP", 10000, json.dumps({
        "status": "pending",
        "session_id": session_id
        }))
    data = {
        "status": "pending",
        "request_id": request_id,
        "session_id": session_id,
        "authorization_request": authorization_request,
        "qr_code_base64": generate_qr_base64(authorization_request)
    }
    logging.info("Response MCP tools 1 wirt QR code")
    return data
    

# request uri endpoint for wallet
def request_uri(stream_id):
    try:
        data = json.loads(red.get(stream_id).decode())
    except Exception:
        logging.info("request expired or already used")
        return jsonify("Request timeout"), 400
    request_as_jwt = data["request_as_jwt"]
    headers = {
        "Content-Type": "application/oauth-authz-req+jwt",
        "Cache-Control": "no-cache"
    }
    return Response(request_as_jwt, headers=headers)


# --- Wallet POSTs VP token response here ---
def response_endpoint(request_id):
    """
    response endpoint for OIDC4VP draft 13, direct_post, no encryption
    """
    logging.info("Enter wallet response endpoint")
    try:
        data = json.loads(red.get(request_id).decode())
    except Exception:
        logging.error("request timeout, data not available in redis")
        return jsonify("Request timeout"), 408

    # get vp_token and presentation_submission
    presentation_submission = request.form.get('presentation_submission')
    vp_token = request.form.get('vp_token')
    if not vp_token or not presentation_submission:   # TODO
        logging.error("Response is incorrect, vp token or presentation submission missing")
        return jsonify("Access denied"), 400

    #presentation_submission = request.form.get('presentation_submission')
    logging.info('vp token received = %s', vp_token)

    # prepare vp_token
    try:
        vp_list = json.loads(vp_token)
    except Exception:
        vp_list = [vp_token]

    n = 1
    signature = validity = True
    error_description = ""
    for vp in vp_list:
        sd_jwt = vp.split("~")
        sd_jwt_payload = helpers.get_payload_from_token(sd_jwt[0])
        
        # check signature
        logging.info("sd-jwt number %s/%s", n, len(vp_list))
        n += 1
        try:
            helpers.verif_token(sd_jwt[0], sd_jwt[-1], data['nonce'], data['aud'])
            signature *= True
        except Exception as e:
            logging.warning("signature check failed = %s", str(e))
            error_description = sd_jwt_payload["vct"] + " signature check failed"
            signature *= False
        
        # Check expiration date
        if sd_jwt_payload.get('exp') and sd_jwt_payload.get('exp') < round(datetime.timestamp(datetime.now())):
            validity *= False
            error_description += " " + sd_jwt_payload["vct"] + " Expired "
        else:
            validity *= True
        
        # extract disclosure
        nb_disclosure = len(sd_jwt)
        logging.info("nb of disclosure = %s", nb_disclosure - 2)
        claims = {}
        claims.update(sd_jwt_payload)
        for i in range(1, nb_disclosure-1):
            _disclosure = sd_jwt[i]
            _disclosure += "=" * ((4 - len(_disclosure) % 4) % 4)
            try:
                logging.info("disclosure #%s = %s", i, base64.urlsafe_b64decode(_disclosure.encode()).decode())
                disc = base64.urlsafe_b64decode(_disclosure.encode()).decode()
                claims.update({json.loads(disc)[1]: json.loads(disc)[2]})
            except Exception:
                logging.error("i = %s", i)
                logging.error("_disclosure excluded = %s", _disclosure)
    
    session_id = json.loads(red.get(request_id + "_MCP").decode())["session_id"]

    claims.pop("status", None)
    claims.pop("_sd", None)
    claims.pop("iss", None)
    claims.pop("cnf", None)
    claims.pop("vct", None)
    claims.pop("_sd_alg", None)
    claims.pop("exp", None)
    claims.pop("iat", None)
    
    session_data = {
            'request_id': request_id,
            'session_id': session_id, 
        }
    if error_description:
        session_data.update({
            'verified': False,
            'message': "We received an error response from the wallet"
        })
    else:
        session_data.update({
            "verified": True,
            'message': "Data has been sent by user's wallet : " + json.dumps(wrap_with_verification(claims))
        })        
        # store verified data
        red.setex(session_id + "_verified_claims", 1000, json.dumps(wrap_with_verification(claims)))

    # publish data to front
    red.publish('chatbot', json.dumps(session_data))

    # delete request and return to wallet
    red.delete(request_id)
    return jsonify('ok')


def wrap_with_verification(data_dict):
    return {
        key: {
            "value": value,
            "verified": True
        }
        for key, value in data_dict.items()
    }


# --- Tools GPT Function calling
def tools():
    data = {
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "initiate_oidc4vp_request",
                    "description": "Displays a QR code or a button that allows the user to share verified identity data from their digital wallet (such as first name, last name, or other credentials). Only use this tool if the user confirms they have a wallet and explicitly agrees to use it. Do not call this tool if the user refuses or if the data has already been verified.",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "create_customer_account",
                    "description": "Creates a customer account using the user's provided personal information.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "given_name": { "type": "string", "description": "User's first name"},
                            "family_name": { "type": "string", "description": "User's last name"},
                            "birth_date": { "type": "string", "description": "User's birth data"},
                            "email": { "type": "string", "description": "User's email address"},
                            "address": { "type": "string", "description": "User's postal address"},
                            "phone": { "type": "string", "description": "User's phone number" }
                        },
                        "required": ["given_name", "family_name", "birth_date", "email"],
                        "strict": True
                    }
                }
            }
        ]
    }
    return data["tools"]


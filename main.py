from flask import Flask, request,  jsonify, Response
import json
import uuid
from datetime import datetime
from urllib.parse import urlencode
import logging
import base64
from jwcrypto import jwk, jwt
import helpers
import x509_attestation
import environment
import redis
import os
import requests


logging.basicConfig(level=logging.INFO)

VERSION = "2.1"


myenv = os.getenv('MYENV')
if not myenv:
    myenv = 'local'
mode = environment.currentMode(myenv)


# Redis init red = redis.StrictRedis()
red = redis.Redis(host='localhost', port=6379, db=0)
app = Flask(__name__) 
app.jinja_env.globals['Version'] = VERSION


def get_verifier_data(verifier_id: str) -> dict:
    try:
        f = open('verifier-profile_2.0.json', 'r')
        return json.loads(f.read())[verifier_id]
    except Exception:
        logging.warning("verifier does not exist")
        return {}
    

@app.route('/', methods=['GET'])
def hello():
    return jsonify("hello Version = " + VERSION)


def build_jwt_request(key, kid, authorization_request) -> str:
    """
    For wallets natural person as jwk is added in header
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types
    """
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


@app.route('/verifier/<client_id>', methods=['GET', 'POST'])
def login_qrcode(client_id):
    logging.info(request.form)
    client_data = get_verifier_data(client_id)
    if request.headers["X-API-Key"] != client_data["X-API-Key"]:
        return jsonify("error api key"), 400
    stream_id = str(uuid.uuid1())
    nonce = str(uuid.uuid1())

    authorization_request = { 
        "response_type": "vp_token",
        "nonce": nonce,
        "response_uri": mode.server + 'verifier/response_uri/' + stream_id,
        "client_id_scheme": "did",
        "client_id": client_data['did'],
        "aud": 'https://self-issued.me/v2',
        "client_metadata": json.load(open("verifier_metadata.json", 'r')),
        "response_mode": 'direct_post',
        "presentation_definition": request.json['presentation_definition']
    }
    logging.info("authorization request = %s", json.dumps(authorization_request, indent=4) )
    if request.json.get("state"):
        authorization_request["steate"] = request.json.get("state")
        
    # manage request as jwt  
    request_as_jwt = build_jwt_request(
        client_data['jwk'],
        client_data['verificationMethod'],
        authorization_request
    )
    payload = {
        "request_as_jwt": request_as_jwt,
        "webhook": request.json['webhook'],
        "nonce": nonce,
        "state": request.json['state']
    }
    red.setex(stream_id, 1000, json.dumps(payload))
    authorization_request_displayed = { 
            "client_id":  client_data['did'],
            "request_uri": mode.server + "verifier/request_uri/" + stream_id 
        }
    QRcode = "openid-vc://" + '?' + urlencode(authorization_request_displayed)
    print(QRcode)
    print("authorization request = ", authorization_request_displayed)
    return jsonify({"QRcode": QRcode})


@app.route('/verifier/request_uri/<stream_id>', methods=['GET', 'POST'])
def request_uri(stream_id):
    try:
        data = json.loads(red.get(stream_id).decode())
    except Exception:
        return jsonify("Request timeout"), 408
    request_as_jwt = data["request_as_jwt"]
    headers = {
        "Content-Type": "application/oauth-authz-req+jwt",
        "Cache-Control": "no-cache"
    }
    return Response(request_as_jwt, headers=headers)


def provide_format(vp, type="vp"):
    if not vp:
        return "no token"
    elif isinstance(vp, dict):
        vp = json.dumps(vp)
    if vp[:1] == "{":
        return "ldp_" + type
    elif len(vp.split("~")) > 1:
        return "vc+sd-jwt"
    else:
        return "jwt_" + type + "_json"
    

@app.route('/verifier/response_uri/<stream_id>',  methods=['POST'])
def response_endpoint(stream_id):
    logging.info("Enter wallet response endpoint")
    try:
        data = json.loads(red.get(stream_id).decode())
    except Exception:
        return jsonify("Request timeout"), 408
    
    # get id_token, vp_token and presentation_submission
    vp_token = request.form.get('vp_token')
    presentation_submission = request.form.get('presentation_submission')
    logging.info('vp token received = %s', vp_token)
    
    if presentation_submission:
        logging.info('presentation submission received = %s', presentation_submission)
    else:
        logging.info('No presentation submission received')    
        
    # check vp_token
    vp_format = provide_format(vp_token)
    if vp_token and vp_format == "vc+sd-jwt":
        vcsd_jwt = vp_token.split("~")
        vcsd_jwt_payload = helpers.get_payload_from_token(vcsd_jwt[0])
        
        # check signature
        try:
            print(vcsd_jwt[0])
            helpers.verif_token(vcsd_jwt[0], False, aud=None)
            signature = True
        except Exception as e:
            print("error = ",e)
            signature = False
        
        # Check expiration date
        if vcsd_jwt_payload.get('exp') and vcsd_jwt_payload.get('exp') < round(datetime.timestamp(datetime.now())):
            validity = False
        else:
            validity = True
            
        nb_disclosure = len(vcsd_jwt)
        logging.info("nb of disclosure = %s", nb_disclosure - 2 )
        claims = {}
        for i in range(1, nb_disclosure-1):
            _disclosure = vcsd_jwt[i]
            _disclosure += "=" * ((4 - len(_disclosure) % 4) % 4)
            try:
                logging.info("disclosure #%s = %s", i, base64.urlsafe_b64decode(_disclosure.encode()).decode())
                disc = base64.urlsafe_b64decode(_disclosure.encode()).decode()
                claims.update({json.loads(disc)[1]: json.loads(disc)[2]})
            except Exception:
                logging.error("i = %s", i)
                logging.error("_disclosure excluded = %s", _disclosure)
    else:
        return jsonify("VP format not supported"), 400
        
    response = {
        "raw": request.form,
        "created": datetime.timestamp(datetime.now()),
        "signature": signature, # bool
        "validity": validity, # bool
        "claims": claims,
        "state": data['state']
    }     
    
    headers = {'Content-Type': 'application/json'}
    requests.post(data['webhook'], headers=headers, json=response) 
    red.delete(stream_id)
    return jsonify('ok')



if __name__ == '__main__':
    app.run(host=mode.flaskserver,
            port=mode.port,
            debug=True,
            threaded=True)

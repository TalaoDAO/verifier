from flask import Flask, request,  jsonify, Response, redirect
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
import os
import requests
import contextlib
import message
import socket
from hashlib import sha256

logging.basicConfig(level=logging.INFO)
VERSION = "2.2"
myenv = os.getenv('MYENV')
red = redis.Redis(host='localhost', port=6379, db=0)
app = Flask(__name__)
app.jinja_env.globals['Version'] = VERSION


def extract_ip():
    st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        st.connect(('10.255.255.255', 1))
        IP = st.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        st.close()
    return IP


def server():
    if myenv == 'aws':
        return 'https://verifier.wallet-provider.com/'
    else:
        return 'http://' + extract_ip() + ':3000/'


def get_verifier_data(verifier_id: str) -> dict:
    try:
        f = open('verifier-profile.json', 'r')
        return json.loads(f.read())[verifier_id]
    except Exception:
        logging.warning("verifier does not exist")
        return {}


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

    
@app.errorhandler(500)
def error_500(e):
    message.message("Error 500 on verifier = " + str(e), 'thierry.thevenet@talao.io', str(e))
    return redirect(server() + '/')


@app.route('/', methods=['GET'])
def hello():
    return jsonify("hello Version = " + VERSION)


@app.route('/verifier/<client_id>', methods=['POST'])
def login_qrcode(client_id):
    logging.info(request.form)
    client_data = get_verifier_data(client_id)
    if request.headers["X-API-Key"] != client_data["X-API-Key"]:
        return jsonify("error api key"), 400
    try:
        presentation_definition = request.json['presentation_definition']
        state = request.json['state']
        webhook = request.json['webhook']
    except Exception:
        return jsonify("invalid request"), 400
        
    stream_id = sha256(state.encode()).hexdigest()
    nonce = str(uuid.uuid1())

    authorization_request = {
        "response_type": "vp_token",
        "nonce": nonce,
        "response_uri": server() + 'verifier/response_uri/' + stream_id,
        "client_id_scheme": "did",
        "client_id": client_data['did'],
        "aud": 'https://self-issued.me/v2',
        "client_metadata": json.load(open("verifier_metadata.json", 'r')),
        "response_mode": 'direct_post',
        "presentation_definition": presentation_definition,
        "state": state
    }
    logging.info("authorization request = %s", json.dumps(authorization_request, indent=4))
        
    # manage request as jwt
    request_as_jwt = build_jwt_request(
        client_data['jwk'],
        client_data['verificationMethod'],
        authorization_request
    )
    payload = {
        "request_as_jwt": request_as_jwt,
        "webhook": webhook,
        "nonce": nonce,
        "aud": client_data['did'],
        "state": state,
        "raw": client_data.get('raw')
    }
    red.setex(stream_id, 1000, json.dumps(payload))
    authorization_request_displayed = { 
            "client_id":  client_data['did'],
            "request_uri": server() + "verifier/request_uri/" + stream_id 
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
        logging.info("request expired or already used")
        return jsonify("Request timeout"), 400
    request_as_jwt = data["request_as_jwt"]
    headers = {
        "Content-Type": "application/oauth-authz-req+jwt",
        "Cache-Control": "no-cache"
    }
    return Response(request_as_jwt, headers=headers)


@app.route('/verifier/response_uri/<stream_id>',  methods=['POST'])
def response_endpoint(stream_id):
    """
    response endpoint for OIDC4VP draft 13, direct_post, no encryption
    """
    logging.info("Enter wallet response endpoint")
    try:
        data = json.loads(red.get(stream_id).decode())
    except Exception:
        logging.error("request timeout, data not available in redis")
        return jsonify("Request timeout"), 408

    # get vp_token and presentation_submission
    vp_token = request.form.get('vp_token')
    presentation_submission = request.form.get('presentation_submission')
    logging.info('vp token received = %s', vp_token)

    if not presentation_submission or not vp_token:
        logging.info('No presentation submission or vp_token received')
        response = {
            "error": "invalid_wallet_request",
            "error_description": "No presentation submission or vp_token received from wallet"
        }
        headers = {'Content-Type': 'application/json'}
        requests.post(data['webhook'], headers=headers, json=response, timeout=10)
        return jsonify('Invalid response format'), 400

    # prepare vp_token
    try:
        vp_list = json.loads(vp_token)
    except Exception:
        vp_list = [vp_token]

    claims_list = []
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
            error_description = sd_jwt_payload["vct"] + str(e)
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
        
        # clean claims for response to application
        with contextlib.suppress(Exception):
            del claims['_sd']
            del claims['cnf']
            del claims['status']
            del claims['iat']
            del claims['exp']
            del claims['_sd_alg']
        claims_list.append(claims)

    # prepare response to application    
    response = {
        "created": datetime.timestamp(datetime.now()),
        "signature": bool(signature),  # bool
        "validity": bool(validity),  # bool
        "claims": claims_list,
        "state": data['state']
    }
    if data['raw']:
        response['raw'] = request.form
    if error_description:
        response['error_description'] = error_description

    # send response to application webhook
    headers = {'Content-Type': 'application/json'}
    requests.post(data['webhook'], headers=headers, json=response, timeout=10)
    logging.info("data sent to application = %s", json.dumps(response, indent=4))

    # delete request
    red.delete(stream_id)
    return jsonify('ok')


if __name__ == '__main__':
    app.run(host=extract_ip(),
            port=3000,
            debug=True,
            threaded=True)

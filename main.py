"""
MCP server to allow an AI agent to acces a wallet PID

"""
# --- Import required libraries ---
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
import io
import message
import socket
import qrcode


# --- Configuration and Initialization ---
logging.basicConfig(level=logging.INFO)
VERSION = "3.9"
myenv = os.getenv('MYENV')
red = redis.Redis(host='localhost', port=6379, db=0)
# Initialize Flask app and inject version into templates
app = Flask(__name__)
app.jinja_env.globals['Version'] = VERSION



# --- Basic Routes ---
@app.route('/', methods=['GET'])
def hello():
    return jsonify("hello Version = " + VERSION)


@app.errorhandler(500)
def error_500(e):
    message.message("Error 500 on verifier = " + str(e), 'thierry.thevenet@talao.io', str(e))
    return redirect(get_server_url())



# --- Utility to get local IP address ---
def extract_ip():
    st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        st.connect(('10.255.255.255', 1))
        ip = st.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        st.close()
    return ip



# --- Determine callback server URL based on environment ---
def get_server_url():
    if myenv == 'aws':
        return 'https://verifier.wallet-provider.com/'
    else:
        return 'http://' + extract_ip() + ':3000/'



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


# provide qrcode for pid

# --- Generate QR code URL and session data for PID verification ---
def get_qrcode(client_id, session_id):
    verifier_data = get_verifier_data(client_id)
    presentation_definition = verifier_data['presentation_definition']
    nonce = str(uuid.uuid1())

    authorization_request = {
        "response_type": "vp_token",
        "nonce": nonce,
        "response_uri": get_server_url() + 'verifier/response_uri/' + session_id,
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
        "state": session_id,
        "raw": verifier_data.get('raw')
    }
    red.setex(session_id, 1000, json.dumps(payload))
    authorization_request_displayed = { 
            "client_id":  verifier_data['did'],
            "request_uri": get_server_url() + "verifier/request_uri/" + session_id 
        }
    qrcode_content = "openid-vc://" + '?' + urlencode(authorization_request_displayed)
    logging.info("QRcode = %s", qrcode_content)
    logging.info("authorization request = %s", authorization_request_displayed)
    return qrcode_content


# Tool MCP 1 : démarrer une demande OIDC4VP

# --- Tool MCP 1: Start OIDC4VP PID Request ---
@app.route("/mcp/initiate_pid_request", methods=["POST", "GET"])
def initiate_oidc4vp_request():
    session_id = str(uuid.uuid4())
    presentation_url = get_qrcode("pid", session_id)
    red.setex(session_id + "_MCP", 10000, json.dumps({"status": "pending"}))
    data = {
        "status": "pending",
        "instructions": "Scan this QR code with your wallet to present a credential.",
        "session_id": session_id,
        "presentation_url": presentation_url,
        "qr_code_base64": generate_qr_base64(presentation_url)
    }
    logging.info("Response MCP 1 = %s", json.dumps(data, indent=4))
    return jsonify(data)
    

# request uri endpoint for wallet

# --- Wallet fetches request JWT here ---
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


# response uri endpoint for wallet

# --- Wallet POSTs VP token response here ---
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
    
    session_id = stream_id
    if error_description:
        session_data = {
            'status': 'error',
            'error_description': error_description
        }
    else:
        session_data = {
            'status': "verified",
            'credential': {
                "given_name": claims['given_name'],
                "family_name": claims["family_name"],
                "birth_date": claims["birth_date"]
            }
        }
    red.setex(session_id + "_MCP", 1000, json.dumps(session_data))

    # delete request and return to wallet
    red.delete(session_id)
    return jsonify('ok')


# Tool MCP 2 

# --- Tool MCP 2: Check result of verification ---
@app.route("/mcp/check_pid_result", methods=["POST", "GET"])
def check_oidc4vp_result():
    data = request.json
    session_id = data.get("session_id")

    if not red.get(session_id + "_MCP"):
        return jsonify({"error": "Invalid session_id"}), 404
    status = json.loads(red.get(session_id + "_MCP").decode())["status"]
    if status == "pending":
        data = {"status": "pending"}
    elif status == "error":
        data = json.loads(red.get(session_id + "_MCP").decode())
    else:
        data = {
            "status": "verified",
            "verified_credential": json.loads(red.get(session_id + "_MCP").decode())['credential']
        }
    logging.info("Response MCP 2 = %s", json.dumps(data, indent=4))
    return jsonify(data)


# Endpoint MCP : déclaration des tools disponibles

# --- MCP Tools Description Endpoint ---
@app.route("/.well-known/mcp/tools", methods=["GET"])
def tools():
    return jsonify({
        "tools": [
            {
                "name": "initiate_pid_request",
                "description": "Initiates an OIDC4VP credential presentation request",
                "input_schema": {
                    "type": "object",
                    "properties": None
                },
                "method": "POST",
                "endpoint":  get_server_url() + "mcp/initiate_pid_request"
            },
            {
                "name": "check_pid_result",
                "description": "Checks the result of a credential presentation via OIDC4VP",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"}
                    },
                    "required": ["session_id"]
                },
                "method": "POST",
                "endpoint": get_server_url() + "mcp/check_pid_result"
            }
        ]
    })



# --- Run the Flask server ---
if __name__ == '__main__':
    app.run(host=extract_ip(),
            port=3000,
            debug=True,
            threaded=True)

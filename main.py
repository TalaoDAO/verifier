from flask import Flask, redirect, request, session, jsonify, Response, render_template
from flask_qrcode import QRcode
from flask_mobility import Mobility
import json
import uuid
from datetime import timedelta, datetime
from urllib.parse import urlencode, quote
import logging
import base64
from jwcrypto import jwk, jwt
import pkce 
import helpers
import x509_attestation
import environment
import redis
import os
import time


logging.basicConfig(level=logging.INFO)

# customer application 
ACCESS_TOKEN_LIFE = 2000
CODE_LIFE = 2000

# wallet
QRCODE_LIFE = 2000

VERSION = "1.0"

# OpenID key of the OP for customer application
key = json.load(open("keys.json", "r"))['RSA_key']
key = jwk.JWK(**key)
public_key = key.export(private_key=False, as_dict=True)

myenv = os.getenv('MYENV')
if not myenv:
    myenv = 'local'
mode = environment.currentMode(myenv)


# Redis init red = redis.StrictRedis()
red = redis.Redis(host='localhost', port=6379, db=0)

app = Flask(__name__) 
app.jinja_env.globals['Version'] = VERSION
app.jinja_env.globals['Created'] = time.ctime(os.path.getctime('main.py'))
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'verifier'
app.config['SESSION_TYPE'] = 'redis' # Redis server side session
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # cookie lifetime
app.config['SESSION_FILE_THRESHOLD'] = 100
app.config['SECRET_KEY'] = "verifier"

qrcode = QRcode(app)
Mobility(app)


def get_verifier_data(verifier_id: str) -> dict:
    try:
        f = open('verifier-profile.json', 'r')
        return json.loads(f.read())[verifier_id]
    except Exception:
        logging.warning("verifier does not exist")
        return {}
    

@app.route('/', methods=['GET'])
def hello():
    return jsonify("hello")



def build_id_token(client_id, vp_token, nonce, vp_format):
    """
    Build an Id_token for application 
    """
    verifier_key = jwk.JWK(**key) 
    header = {
        "typ": "JWT",
        "kid": key['kid'],
        "alg": helpers.alg(key)
    }
    payload = {
        "iss": mode.server + 'verifier/app',
        "iat": datetime.timestamp(datetime.now()),
        "aud": client_id,
        "sub": 'https://self-issued.me/v2',
        'exp': datetime.timestamp(datetime.now()) + 1000
    }
    if nonce:
        payload['nonce'] = nonce
    
    if vp_format == "vc+sd-jwt":
        vcsd = vp_token.split("~")
        vcsd_jwt_payload = helpers.get_payload_from_token(vcsd[0])
        payload['vc'] = {
            "iss": vcsd_jwt_payload['iss'],
            "iat": vcsd_jwt_payload['iat'],
            "exp": vcsd_jwt_payload['iat'],
            "cnf": vcsd_jwt_payload['cnf'],
            "status": vcsd_jwt_payload['status'],
            "vct": vcsd_jwt_payload['vct']
        }
        #vcsd_jwt_header = helpers.get_header_from_token(vcsd[0])
        for i in range(1, len(vcsd)-1):
            disclosure = vcsd[i]
            disclosure += "=" * ((4 - len(vcsd[i]) % 4) % 4)    
            disclosure = base64.urlsafe_b64decode(disclosure.encode()).decode()
            disclosure = json.loads(disclosure)
            payload["vc"][disclosure[1]] = disclosure[2]
    else:
        vp_token = helpers.get_payload_from_token(vp_token)
        vc_token = vp_token["vp"]["verifiableCredential"][0]
        vc_token = helpers.get_payload_from_token(vc_token)
        if email := vc_token["vc"]["credentialSubject"].get('email'):
            payload["email"] = email
        elif phone := vp_token["vp"]["credentialSubject"].get('phone'):
            payload['phone'] = phone
        payload['sub'] = vp_token.get('sub')
        
    logging.info("ID token payload = %s", payload)
    application_token = jwt.JWT(header=header, claims=payload, algs=[helpers.alg(key)])
    application_token.make_signed_token(verifier_key)
    return application_token.serialize()


@app.route('/verifier/app/jwks.json', methods=['GET'])
def jwks():
    return jsonify({"keys": [public_key]})


# For customer app
@app.route('/verifier/app/.well-known/openid-configuration', methods=['GET'])
def openid_configuration():
    return {
        "issuer": mode.server + 'verifier/app',
        "authorization_endpoint":  mode.server + 'verifier/app/authorize',
        "token_endpoint": mode.server + 'verifier/app/token',
        "userinfo_endpoint": mode.server + 'verifier/app/userinfo',
        "logout_endpoint": mode.server + 'verifier/app/logout',
        "jwks_uri": mode.server + 'verifier/app/jwks.json',
        "scopes_supported": ["openid", "pid", "email"],
        "response_types_supported": ["code", "id_token"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post"]
    }


# authorization server for customer application
"""
response_type supported = code or id_token or vp_token
code -> authorization code flow
id_token -> implicit flow
# https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
"""


@app.route('/verifier/app/authorize',  methods=['GET', 'POST'])
def authorize():
    """     
    https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2
    code_wallet_data = 
    {
        "vp_token_payload",: xxxxx
        "sub": xxxxxx
    }
    """
    # user is connected, successful exit to client with code
    if session.get('verified') and request.args.get('code'):
        code = request.args['code']
        try:
            code_data = json.loads(red.get(code).decode())
        except Exception:
            logging.error("code expired")
            resp = {'error': "access_denied"}
            redirect_uri = session['redirect_uri']
            sep = session['sep']
            session.clear()
            return redirect(redirect_uri + sep + urlencode(resp)) 

        # authorization code flow -> redirect with code
        if code_data['response_type'] == 'code':
            logging.info("response_type = code: successful redirect to client with code = %s", code) 
            resp = {'code': code,  'state': code_data.get('state')} if code_data.get('state') else {'code': code}
            logging.info('response to redirect_uri = %s', resp)
            return redirect(code_data['redirect_uri'] + '?' + urlencode(resp))

        # implicit flow -> redirect with id_token 
        elif code_data['response_type'] == 'id_token':
            logging.info("response_type = id_token") 
            sep = "?" if code_data['response_mode'] == 'query' else "#"
            session['sep'] = sep
            try:
                code_wallet_data = json.loads(red.get(code + "_wallet_data").decode())
            except Exception:
                logging.error("code expired")
                resp = {'error': "access_denied"}
                redirect_uri = code_data['redirect_uri']
                session.clear()
                return redirect(redirect_uri + sep + urlencode(resp)) 
            id_token = build_id_token(code_data['client_id'],code_wallet_data['vp_token_payload'],code_data['nonce'],code_wallet_data['vp_format'])
            resp = {"id_token": id_token} 
            redirect_url = code_data['redirect_uri'] + sep + urlencode(resp)
            return redirect(redirect_url)

        else:
            logging.error("session expired")
            resp = {'error': "access_denied"}
            redirect_uri = code_data['redirect_uri']
            session.clear()
            return redirect(redirect_uri + '?' + urlencode(resp)) 

    # error in login, exit, clear session
    if 'error' in request.args:
        logging.warning('Error in the login process, redirect to client with error code = %s', request.args['error'])
        code = request.args['code']
        code_data = json.loads(red.get(code).decode())
        resp = {'error': request.args['error']}
        if code_data.get('state'):
            resp['state'] = code_data['state']
        redirect_uri = code_data['redirect_uri']
        red.delete(code)
        session.clear()
        return redirect(redirect_uri + '?' + urlencode(resp)) 
    
    # User is not connected
    def manage_error_request(msg):
        session.clear()
        resp = {'error': msg}
        return redirect(request.args['redirect_uri'] + '?' + urlencode(resp))
        
    session['verified'] = False
    logging.info('user is not connected in OP')
    try:
        data = {
            'client_id': request.args['client_id'],  # required
            'scope': request.args['scope'].split(),  # required
            'state': request.args.get('state'),
            'response_type': request.args['response_type'],  # required
            'redirect_uri': request.args['redirect_uri'],  # required
            'nonce': request.args.get('nonce'),
            'code_challenge': request.args.get('code_challenge'),
            'code_challenge_method': request.args.get('code_challenge_method'),
            "expires": datetime.timestamp(datetime.now()) + CODE_LIFE,
            'response_mode': request.args.get('response_mode')
        }
    except Exception:
        logging.warning('invalid request received in authorization server')
        try:
            return manage_error_request("invalid_request_object")
        except Exception:
            session.clear()
            return jsonify('request malformed'), 400
    verifier_data = get_verifier_data(request.args['client_id'])
    if not verifier_data:
        logging.warning('client_id not found in verifier database')
        return manage_error_request("unauthorized_client")

    session['redirect_uri'] = request.args['redirect_uri']
    if request.args['response_type'] not in ["code", "id_token"]:
        logging.warning('unsupported response type %s', request.args['response_type'])
        return manage_error_request("unsupported_response_type")

    # creation grant = code
    code = str(uuid.uuid1())
    red.setex(code, CODE_LIFE, json.dumps(data))
    resp = {'code': code}
    return redirect('/verifier/wallet?code=' + code)


# token endpoint for customer application
@app.route('/verifier/app/token', methods=['GET', 'POST'])
def token():
    #https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
    logging.info("token endpoint request ")
    
    def manage_error(error, error_description=None, status=400):
        logging.warning(error)
        endpoint_response = {"error": error}
        if error_description:
            endpoint_response['error_description'] = error_description
        headers = {
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            'Content-Type': 'application/json'
        }
        return Response(response=json.dumps(
            endpoint_response),
            status=status,
            headers=headers
        )
        
    try:
        _token = request.headers['Authorization']
        _token = _token.split(" ")[1]
        _token = base64.b64decode(_token).decode()
        client_secret = _token.split(":")[1]
        client_id = _token.split(":")[0]
        logging.info('Authentication client_secret_basic')
    except Exception:
        try:
            client_id = request.form['client_id']
            client_secret = request.form['client_secret']
            logging.info('Authorization client_secret_post')
        except Exception:
            return manage_error("request_not_supported", error_description="Client authentication method not supported")
    try:
        verifier_data = get_verifier_data(client_id)
        grant_type = request.form['grant_type']
        code = request.form['code']
        redirect_uri = request.form['redirect_uri']
    except Exception:
        return manage_error("invalid_request")
    
    code_verifier = request.form.get('code_verifier')

    try:
        code_data = json.loads(red.get(code).decode())
    except Exception:
        logging.error("red get probleme sur code")
        return manage_error("invalid_grant")
    
    verifier_data = get_verifier_data(client_id)
    
    if client_id != code_data['client_id']:
        return manage_error("invalid_client")
    if verifier_data['application_client_secret'] != client_secret:
        return manage_error("invalid_client")
    elif redirect_uri != code_data['redirect_uri']:
        return manage_error("invalid_redirect_uri")
    elif grant_type != 'authorization_code':
        return manage_error("unauthorized_client")
    if not code_verifier:
        logging.warning("Code verifier has not been sent")
    else:
        if pkce.get_code_challenge(code_verifier) != code_data['code_challenge']:
            logging.warning('code verifier not correct')
            return manage_error("unauthorized_client")
    
    # token response
    try:
        code_wallet_data = json.loads(red.get(code + "_wallet_data").decode())
    except Exception:
        logging.error("redis get problem to get code_wallet_data")
        return manage_error("invalid_grant")
    id_token = build_id_token(code_data['client_id'], code_wallet_data['vp_token_payload'], code_data['nonce'], code_wallet_data['vp_format'])
    access_token = str(uuid.uuid1())
    endpoint_response = {
        "id_token": id_token,
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_LIFE
    }
    red.setex(
        access_token + '_wallet_data',
        ACCESS_TOKEN_LIFE,
        json.dumps({
            "client_id": client_id,
            "sub": code_wallet_data['sub'],
            "vp_token_payload": code_wallet_data['vp_token_payload']
        })
    )
    headers = {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        'Content-Type': 'application/json'}
    return Response(response=json.dumps(endpoint_response), headers=headers)


# logout endpoint
#https://openid.net/specs/openid-connect-rpinitiated-1_0-02.html
@app.route('/verifier/app/logout', methods=['GET', 'POST'])
def logout():
    if not session.get('verified'):
        return jsonify('Forbidden'), 403
    if request.method == "GET":
        #  id_token_hint = request.args.get('id_token_hint')
        post_logout_redirect_uri = request.args.get('post_logout_redirect_uri')
    elif request.method == "POST":
        #  id_token_hint = request.form.get('id_token_hint')
        post_logout_redirect_uri = request.form.get('post_logout_redirect_uri')
    if not post_logout_redirect_uri:
        post_logout_redirect_uri = session.get('redirect_uri')
    session.clear()
    logging.info("logout call received, redirect to %s", post_logout_redirect_uri)
    return redirect(post_logout_redirect_uri)


@app.route('/verifier/app/userinfo', methods=['GET', 'POST'])
def userinfo():
    logging.info("user info endpoint request")
    try:
        access_token = request.headers["Authorization"].split()[1]
    except Exception:
        logging.warning("Access token is passed as argument by application")
        access_token = request.args['access_token']

    try:
        wallet_data = json.loads(red.get(access_token + '_wallet_data').decode())
        payload = {
            "sub": 'https://self-issued.me/v2',
            "vp_token_payload": wallet_data["vp_token_payload"]
        }
        headers = {
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Content-Type": "application/json"}
        return Response(response=json.dumps(payload), headers=headers)
    
    except Exception:
        logging.warning("access token expired")
        headers = {'WWW-Authenticate': 'Bearer realm="userinfo", error="invalid_token", error_description = "The access token expired"'}
        return Response(status=401,headers=headers)


    
################################# OIDC4VP ###########################################


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
        'exp': datetime.timestamp(datetime.now()) + 1000
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


def build_verifier_metadata(verifier_id) -> dict:
    verifier_data = get_verifier_data(verifier_id)
    verifier_metadata = json.load(open(verifier_data["oidc4vc"]['verifier_metadata_file'], 'r'))
    verifier_metadata['request_uri_parameter_supported'] = bool(verifier_data["oidc4vc"]['request_uri_parameter_supported'])
    verifier_metadata['request_parameter_supported'] = bool(verifier_data["oidc4vc"]['request_parameter_supported'])
    return verifier_metadata


@app.route('/verifier/wallet/presentation_definition_uri/<verifier_id>',  methods=['GET'])
def presentation_definition_uri(verifier_id):
    verifier_data = get_verifier_data(verifier_id)
    try:
        presentation_definition = json.load(open(verifier_data["oidc4vc"]["presentation_definition_file"], 'r'))
    except Exception:
        return jsonify('Request timeout'), 408
    return jsonify(presentation_definition)


@app.route('/verifier/wallet', methods=['GET', 'POST'])
def login_qrcode():
    stream_id = str(uuid.uuid1())
    try:
        code_data = json.loads(red.get(request.args['code']).decode())
    except Exception:
        logging.error("session expired in login_qrcode")
        return render_template("verifier_session_problem.html", message='Session expired')
    
    verifier_id = code_data['client_id']
    verifier_data = get_verifier_data(verifier_id)
    redirect_uri = mode.server + "verifier/wallet/response/" + stream_id
    
    # Set client_id, request jwt iss and key
    if verifier_data["oidc4vc"]['client_id_scheme'] == "x509_san_dns":
        client_id = "talao.co"
        request_as_jwt_key = verifier_data["oidc4vc"]['jwk']
    elif verifier_data["oidc4vc"]['client_id_scheme'] == "redirect_uri":
        client_id = redirect_uri
        request_as_jwt_key = None
    elif verifier_data["oidc4vc"]['client_id_scheme'] == "did":
        client_id = verifier_data["oidc4vc"]['did']
        request_as_jwt_key = verifier_data["oidc4vc"]['jwk']
    else:
        client_id = verifier_data["oidc4vc"]['did']
        request_as_jwt_key = verifier_data["oidc4vc"]['jwk']    
    
    verifier_metadata = build_verifier_metadata(verifier_id)

    # general authorization request
    authorization_request = { 
        "response_type": "vp_token",
        "state": str(uuid.uuid1()),  # unused
        "response_uri": redirect_uri,
        "client_id_scheme": verifier_data["oidc4vc"]['client_id_scheme'],
        "client_id": client_id,
        "aud": 'https://self-issued.me/v2',
        "nonce": code_data.get('nonce') or str(uuid.uuid1()),
        "client_metadata": verifier_metadata,
        "response_mode": verifier_data["oidc4vc"]['response_mode']
    }
    
    # presentation definition
    if "pid" in code_data["scope"]:
        presentation_definition = json.load(open('presentation-definition/pid.json', 'r'))
    elif "email" in code_data["scope"]:
        presentation_definition = json.load(open('presentation-definition/email.json', 'r'))
    elif "phone" in code_data["scope"]:
        presentation_definition = json.load(open('presentation-definition/phone.json', 'r'))
    else:
        presentation_definition_file = verifier_data["oidc4vc"].get("presentation_definition_file")
        if not presentation_definition_file:
            presentation_definition = json.load(open('presentation-definition/pid.json', 'r'))
        else:
            presentation_definition = json.load(open(presentation_definition_file, 'r'))    

    presentation_definition_uri = mode.server + 'verifier/wallet/presentation_definition_uri/' + verifier_id    
    if verifier_data["oidc4vc"]['presentation_definition_uri']:
        authorization_request['presentation_definition_uri'] = presentation_definition_uri
    else:
        if verifier_data["oidc4vc"]['request_uri_parameter_supported']:
            authorization_request['presentation_definition'] = presentation_definition 

    # store data
    data = { 
        "pattern": authorization_request,
        "code": request.args['code'],
        "client_id": client_id,
        "verifier_id": verifier_id
    }
    red.setex(stream_id, QRCODE_LIFE, json.dumps(data))

    # manage request as jwt  
    request_as_jwt = build_jwt_request(
        request_as_jwt_key,
        verifier_data["oidc4vc"]['verificationMethod'],
        authorization_request
    )

    # QRCode preparation with authorization_request_displayed
    if verifier_data["oidc4vc"]['request_uri_parameter_supported']: # request uri as jwt
        data = {
            "key": request_as_jwt_key,
            "kid": verifier_data["oidc4vc"]["verificationMethod"],
            "authorization_request": authorization_request
        }
        red.setex("request_uri_" + stream_id, QRCODE_LIFE, json.dumps(data))
        authorization_request_displayed = { 
            "client_id": client_id,
            "request_uri": mode.server + "verifier/wallet/request_uri/" + stream_id 
        }
    elif verifier_data["oidc4vc"]['request_parameter_supported']:
        authorization_request['request'] = request_as_jwt
        authorization_request_displayed = authorization_request
    else:
        authorization_request_displayed = authorization_request
    
    url = verifier_data["oidc4vc"]["prefix"] + '?' + urlencode(authorization_request_displayed)

    if not verifier_data["oidc4vc"]['request_uri_parameter_supported']:
        url += '&client_metadata=' + quote(json.dumps(verifier_metadata))
        if not verifier_data["oidc4vc"]['presentation_definition_uri']:
            url += '&presentation_definition=' + quote(json.dumps(presentation_definition))

    # test qrcode size
    if len(url) > 2900:
        logging.info("qrcode qize = %s", len(url))
        return jsonify("This QR code is too big, use request uri")
    
    return render_template(
        verifier_data["oidc4vc"]['verifier_landing_page'],
        url=url,
        stream_id=stream_id,
        page_title=verifier_data["oidc4vc"].get('page_title', ""),
        page_subtitle=verifier_data["oidc4vc"].get('page_subtitle', ""),
        code=request.args['code'],
        navbar=verifier_data["oidc4vc"].get('navbar')
    )


@app.route('/verifier/wallet/request_uri/<stream_id>', methods=['GET', 'POST'])
def request_uri(stream_id):
    """
    Request URI
    https://www.rfc-editor.org/rfc/rfc9101.html
    updated with request URI POST method OIDC4VP Draft 21
    """
    try:
        data = json.loads(red.get("request_uri_" + stream_id).decode())
    except Exception:
        return jsonify("Request timeout"), 408
    if request.method == 'GET':
        logging.info('GET request URI')
    elif request.method == 'POST':
        logging.info('POST Request URI header = %s', request.headers)
        if wallet_nonce := request.form.get("wallet_nonce"):
            data['authorization_request']["wallet_nonce"] = wallet_nonce
        if wallet_metadata := request.form.get("wallet_metadata"):
            logging.info(wallet_metadata)
    else:
        return jsonify("Unauthorized"), 404
    request_as_jwt = build_jwt_request(
                data["key"],
                data["kid"],
                data["authorization_request"]
            )
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
    

@app.route('/verifier/wallet/response/<stream_id>',  methods=['POST']) # redirect_uri for POST
def response_endpoint(stream_id):
    logging.info("Enter wallet response endpoint")

    response_format = "Unknown"
    state_status = 'unknown'
    presentation_submission_status = "Unknown"
    aud_status = "unknown"
    nonce_status = "Unknown"
    access = True
    qrcode_status = "Unknown"

    try:
        qrcode_status = "ok"
        data = json.loads(red.get(stream_id).decode())
        verifier_id = data['verifier_id']
    except Exception:
        qrcode_status = "QR code expired"
        logging.info("QR code expired")
        access = False
        vp_token = False

    # get id_token, vp_token and presentation_submission
    if access:
        if request.form.get('response'):
            response = helpers.get_payload_from_token(request.form['response'])
            logging.info("JARM mode")
            # TODO check JARM signature
        else:
            response = request.form
        vp_token = response.get('vp_token')
        presentation_submission = response.get('presentation_submission')
        response_format = "ok"
        logging.info('vp token received = %s', vp_token)
    
    if presentation_submission:
        logging.info('presentation submission received = %s', presentation_submission)
        presentation_submission_status = "ok"
    else:
        logging.info('No presentation submission received')    
        presentation_submission_status = "Not received"
        access = False
        
    # check vp_token
    vp_format = provide_format(vp_token)
    if vp_token and vp_format == "vc+sd-jwt":
        vcsd_jwt = vp_token.split("~")
        nb_disclosure = len(vcsd_jwt)
        logging.info("nb of disclosure = %s", nb_disclosure - 2 )
        disclosure = []
        for i in range(1, nb_disclosure-1):
            _disclosure = vcsd_jwt[i]
            _disclosure += "=" * ((4 - len(_disclosure) % 4) % 4)
            try:
                logging.info("disclosure #%s = %s", i, base64.urlsafe_b64decode(_disclosure.encode()).decode())
                disc = base64.urlsafe_b64decode(_disclosure.encode()).decode()
                disclosure.append(disc)
            except Exception:
                logging.error("i = %s", i)
                logging.error("_disclosure excluded = %s", _disclosure)
        logging.info("vp token signature not checked yet")
    if vp_token and vp_format == "jwt_vp_json":
        pass
        
    detailed_response = {
        "created": datetime.timestamp(datetime.now()),
        "qrcode_status": qrcode_status,
        "state": state_status,
        "presentation_submission_status": presentation_submission_status,
        "nonce_status": nonce_status,
        "aud_status": aud_status,
        "response_format": response_format,
    }
    if not access:
        response = {
            "error": "access_denied",
            "error_description": json.dumps(detailed_response)
        }
        logging.info("Access denied")
        status_code = 400
    else:
        response = "{}"
        status_code = 200
    
    logging.info("response detailed = %s", json.dumps(detailed_response, indent=4))
    
    # follow up
    wallet_data = {
        "access": access,
        "vp_token_payload": vp_token,
        "vp_format": vp_format,
    }
    if vp_format == "vc+sd-jwt":
        wallet_data["sub"] = helpers.get_payload_from_token(vcsd_jwt[0])['iss']
    else:
        wallet_data["sub"] = helpers.get_payload_from_token(vp_token)['sub']
        
    red.setex(stream_id + "_wallet_data", CODE_LIFE, json.dumps(wallet_data))
    event_data = json.dumps({"stream_id": stream_id})         
    red.publish('verifier', event_data)
    return jsonify(response), status_code


@app.route('/verifier/wallet/followup',  methods=['GET'])
def login_followup():
    """
    check if user is connected or not and redirect data to authorization server
    Prepare de data to transfer
    create activity record
    """
    logging.info("Enter follow up endpoint")
    try:
        stream_id = request.args.get('stream_id')
        code = json.loads(red.get(stream_id).decode())['code']
    except Exception:
        return jsonify("Forbidden"), 403
    try:
        stream_id_wallet_data = json.loads(red.get(stream_id + '_wallet_data').decode())
    except Exception:
        logging.error("code expired in follow up")
        resp = {
            'code': code,
            'error': "access_denied",
            'error_description': "Session expired"
        }
        session['verified'] = False
        return redirect('/verifier/app/authorize?' + urlencode(resp))

    if not stream_id_wallet_data['access']:
        resp = {
            'code': code,
            'error': 'access_denied',
            'error_description': ""
        }
        session['verified'] = False
    else:
        session['verified'] = True
        red.setex(code + "_wallet_data", CODE_LIFE, json.dumps(stream_id_wallet_data))
        resp = {'code': code}

    return redirect('/verifier/app/authorize?' + urlencode(resp))


@app.route('/verifier/wallet/stream', methods=['GET'])
def login_stream():
    def login_event_stream():
        pubsub = red.pubsub()
        pubsub.subscribe('verifier')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = { "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no"}
    return Response(login_event_stream(), headers=headers)


# For demo
@app.route('/callback', methods=['GET'])
def callback():
    id_token = request.args['id_token']
    id_token = helpers.get_payload_from_token(id_token)
    if email := id_token.get('email'):
        return render_template("welcome.html", page_title="Welcome !", page_subtitle=email)
    if id_token.get("vc"):
        name = id_token["vc"]["given_name"] + " " + id_token["vc"]["family_name"]
        return render_template("welcome.html", page_title="Welcome !",page_subtitle=name)




if __name__ == '__main__':
    app.run(host=mode.flaskserver,
            port=mode.port,
            debug=True,
            threaded=True)

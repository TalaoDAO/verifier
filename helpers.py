import base64
import json
from jwcrypto import jwk, jwt
import requests
import logging

logging.basicConfig(level=logging.INFO)


def get_payload_from_token(token) -> dict:
    if not token:
        return {}
    payload = token.split('.')[1]
    payload += "=" * ((4 - len(payload) % 4) % 4) # solve the padding issue of the base64 python lib
    return json.loads(base64.urlsafe_b64decode(payload).decode())


def get_header_from_token(token) -> dict:
    if not token:
        return {}
    header = token.split('.')[0]
    header += "=" * ((4 - len(header) % 4) % 4) # solve the padding issue of the base64 python lib
    return json.loads(base64.urlsafe_b64decode(header).decode())


def alg(key):
    key = json.loads(key) if isinstance(key, str) else key
    if key['kty'] == 'EC':
        if key['crv'] in ['secp256k1', 'P-256K']:
            key['crv'] = 'secp256k1'
            return 'ES256K'
        elif key['crv'] == 'P-256':
            return 'ES256'
        elif key['crv'] == 'P-384':
            return 'ES384'
        elif key['crv'] == 'P-521':
            return 'ES512'
        else:
            raise Exception("Curve not supported")
    elif key['kty'] == 'RSA':
        return 'RS256'
    elif key['kty'] == 'OKP':
        return 'EdDSA'
    else:
        raise Exception("Key type not supported")


def verif_token(token, nonce, aud=None):
    header = get_header_from_token(token)
    payload = get_payload_from_token(token)
    if nonce and payload.get('nonce') != nonce:
        raise Exception("nonce is incorrect")
    if aud and payload.get('aud') != aud:
        raise Exception("aud is incorrect")
    if header.get('jwk'):
        if isinstance(header['jwk'], str):
            header['jwk'] = json.loads(header['jwk'])
        dict_key = header['jwk']
    elif header.get('kid'):
        if header.get('kid')[:2] == "did":
            dict_key = resolve_did(header['kid'])
        else:
            iss = payload.get('iss')
            scheme = iss.split('//')[0] + "//"
            host = iss.split('//')[1].split('/')[0]
            path = iss.split(scheme + host)[1]
            url = scheme + host + '/.well-known/jwt-vc-issuer'
            if path:
                url = url + path
            resp = requests.get(url)
            api_response = resp.json()
            dict_key = None
            if api_response.get('jwks'):
                keys = api_response.get('jwks')['keys']
            else:
                resp = requests.get(api_response.get('jwks_uri'))
                keys = resp.json()['keys']
            for key in keys:
                if key['kid'] == header.get('kid'):
                    dict_key = key
                    break
        if not dict_key:
            raise Exception("Cannot get public key with kid from sd-jwt")
    elif payload.get('sub_jwk'):
        dict_key = payload['sub_jwk']
    else:
        raise Exception("Cannot resolve public key")
    a = jwt.JWT.from_jose_token(token)
    issuer_key = jwk.JWK(**dict_key)
    a.validate(issuer_key)
    return True


def resolve_did(vm) -> dict:
    try:
        did = vm.split('#')[0]
    except Exception:
        logging.error("This verification method is not supported  %s", vm)
        return 
    if did.split(':')[1] == "jwk":
        key = did.split(':')[2]
        key += "=" * ((4 - len(key) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(key))
    elif did.split(':')[1] == "web":
        logging.info("did:web")
        did_document = resolve_did_web(did)
        for verificationMethod in did_document:
            if vm == verificationMethod['id'] or '#' + vm.split('#')[1] == verificationMethod['id']:
                jwk = verificationMethod.get('publicKeyJwk')
                logging.info('wallet jwk = %s', jwk)
                return jwk
    else:
        logging.info("Talao uniresolver")
        url = 'https://unires:test@unires.talao.co/1.0/identifiers/' + did
        try:
            r = requests.get(url, timeout=5)
            logging.info('Access to Talao Universal Resolver')
        except Exception:
            logging.error('cannot access to Talao Universal Resolver for %s', vm)
            url = 'https://dev.uniresolver.io/1.0/identifiers/' + did
            try:
                r = requests.get(url, timeout=5)
                logging.info('Access to Public Universal Resolver')
            except Exception:
                logging.warning('fails to access to both universal resolver')
                return
        did_document = r.json()
        for verificationMethod in did_document['didDocument']['verificationMethod']:
            if vm == verificationMethod['id'] or '#' + vm.split('#')[1] == verificationMethod['id']:
                jwk = verificationMethod.get('publicKeyJwk')
                if not jwk:
                    publicKeyBase58 = verificationMethod.get('publicKeyBase58')
                    logging.info('wallet publiccKeyBase48 = %s', publicKeyBase58)
                    return publicKeyBase58
                else:  
                    logging.info('wallet jwk = %s', jwk)
                    return jwk
                
                
def resolve_did_web(did) -> str:
    if did.split(':')[1] != 'web':
        return
    url = 'https://' + did.split(':')[2] 
    i = 3
    try:
        while did.split(':')[i]:
            url = url + '/' +  did.split(':')[i]
            i += 1
    except Exception:
        pass
    url = url + '/did.json'
    r = requests.get(url)
    if 399 < r.status_code < 500:
        logging.warning('return API code = %s', r.status_code)
        return "{'error': 'did:web not found on server'}"
    return r.json()
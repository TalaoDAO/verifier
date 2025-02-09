from flask import Flask, jsonify, render_template_string, request, redirect, Response
import requests
from flask_qrcode import QRcode
import uuid
import socket
import redis
import json


# Redis init red = redis.StrictRedis()
red= redis.Redis(host='localhost', port=6379, db=0)



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



ngrok = "https://929af4a49775.ngrok.app"  # pour test
ngrok = "http://" + extract_ip() + ":5000"
verifier = "https://verifier.wallet-provider.com/verifier/"
verifier = "http://" + extract_ip() + ":3000/verifier/"


PRESENTATION_DEFINITION = {
    "id": "over18_with_limited_disclosure",
    "input_descriptors": [
        {
            "id": "over18",
            "format": {
                "vc+sd-jwt": {
                    "sd-jwt_alg_values": [
                        "ES256"
                    ],
                    "kb-jwt_alg_values": [
                        "ES256"
                    ]
        }
            },
            "constraints": {
                "limit_disclosure": "required",
                "fields": [
                    {
                        "path": [
                            "$.age_over_18"
                        ]
                    }
                ]
            }
        },
        {
            "id": "binance_crypto_account_proof",
            "format": {
                "vc+sd-jwt": {
                    "sd-jwt_alg_values": [
                        "ES256"
                    ],
                    "kb-jwt_alg_values": [
                        "ES256"
                    ]
                }
            },
            "constraints": {
                "limit_disclosure": "required",
                "fields": [
                    {
                        "path": [
                            "$.blockchain"
                        ]
                    }
                ]
            }
        }
    ]
}


OVER18_PRESENTATION_DEFINITION = {
    "id": "over18_with_limited_disclosure",
    "input_descriptors": [
        {
            "id": "over18",
            "format": {
                "vc+sd-jwt": {
                    "sd-jwt_alg_values": [
                        "ES256"
                    ],
                    "kb-jwt_alg_values": [
                        "ES256"
                    ]
        }
            },
            "constraints": {
                "limit_disclosure": "required",
                "fields": [
                    {
                        "path": [
                            "$.age_over_18"
                        ]
                    }
                ]
            }
        }
    ]
}

# Init Flask
app = Flask(__name__)
qrcode = QRcode(app)

client_id = "0000"
X_API_Key = "0000"


# ce webhook permet de recuperer le credential envoyé par le wallet
@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    red.setex(data['state'] + "_wallet", 1000, json.dumps(data))
    red.publish('verifier', json.dumps({"stream_id": data['state']}))
    return jsonify('ok')


# ce endpoint permet d'afficher le QR code envoyé par le verifier
@app.route('/', methods=['GET', 'POST'])
def site():
    # on appelle le verifier qui envoie le QR code a afficher sur le site local
    user = str(uuid.uuid1()) # identifient de la session du user
    payload = {
        "presentation_definition": OVER18_PRESENTATION_DEFINITION,
        "webhook": ngrok + '/webhook', # url du webhook du site
        "state": user
    }
    url = verifier + client_id
    headers = {
        'X-API-Key': X_API_Key,
        'Content-Type': 'application/json'
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=10) 
    api_response = resp.json()
    qrcode = api_response['QRcode']
    red.setex(user, 1000, qrcode)
    return redirect('/qrcode/' + user)


@app.route('/qrcode/<user>', methods=['GET', 'POST'])   
def qrcode(user):
    url = red.get(user).decode()
    print('url =', url)
    html_string = """<html>
                        <body>
                            <div>
                                <h1>Verifier app for test</h1>
                                <img  src="{{ qrcode(url) }}" width="400"><br>
                            </div>
                            <script>
                                var source = new EventSource('/stream');
                                source.onmessage = function (event) {
                                    const result = JSON.parse(event.data)
                                    if (result.stream_id == '{{user}}' ){
                                        window.location.href='/followup/' + result.stream_id;
                                    }
                                };
                            </script>
                        </body>
                    </html>"""
    return render_template_string(html_string, user=user, url=url)



@app.route('/followup/<user>', methods=['GET']) 
def followup(user):
    data = red.get(user + "_wallet").decode()
    data = json.dumps(json.loads(data), indent=4)
    html_string = """<html>
                            <h1>Data sent by wallet</h1>
                                <div>
                                    <textarea rows="30" cols="150">{{data|safe}}</textarea>
                                    <br><br>
                                    <a href="/"><button>Reset</button></a>
                                </div>
                            </body>
                        </html>"""
    return render_template_string(html_string, data=data)

    
@app.route('/stream', methods=['GET', 'POST'])
def stream():
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




if __name__ == '__main__':
    app.run(host=extract_ip(), port=5000, debug =True)

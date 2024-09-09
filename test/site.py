from flask import Flask, jsonify, render_template_string, redirect, request
import flask
from flask_session import Session
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession
import redis


# Redis init red = redis.StrictRedis()
red= redis.Redis(host='localhost', port=6379, db=0)

# Init Flask
app = Flask(__name__)
app.config.update(
    OIDC_REDIRECT_URI = 'http://192.168.2.115:5000/callback', # your application redirect uri. Must not be used in your code
    SECRET_KEY = "lkjhlkjh" # your application secret code for session, random
)

# Framework Flask and Session setup
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'talao'
app.config['SESSION_TYPE'] = 'redis' # Redis server side session
app.config['SESSION_FILE_THRESHOLD'] = 100

sess = Session()
sess.init_app(app)


"""
Init OpenID Connect client PYOIDC with the 3 bridge parameters :  client_id, client_secret and issuer URL
"""

client_metadata = ClientMetadata(
     client_id='0001',
    client_secret='0001',
    #post_logout_redirect_uris=['http://127.0.0.1:4000/logout']) # your post logout uri (optional
    )

provider_config = ProviderConfiguration(issuer='http://192.168.2.115:3000/verifier/app',
                                        client_metadata=client_metadata)

auth = OIDCAuthentication({'default': provider_config}, app)


@app.route('/', methods=['GET', 'POST'])
def site():
    if request.method == 'GET' :
        html_string = """<html><head></head>
                        <body><div>
                        <form action="/" method="POST" >                    
                            <button  type"submit" > Generate QR code for WCM </button>
                        </form>
                        
                        </div>
                        </body></html>"""
        return render_template_string(html_string) 
    else:
        return redirect('/login')


@app.route('/login')
@auth.oidc_auth('default')
def index():    
    user_session = UserSession(flask.session)  
    print("Id token = ", user_session.id_token)  
    return jsonify('Congrats') 


@auth.error_view
def error(error=None, error_description=None):
    return jsonify('Sorry')


if __name__ == '__main__':
    app.run( host = "192.168.2.115", port=5000, debug =True)

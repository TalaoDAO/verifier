from flask import Flask, request, jsonify, redirect


app = Flask(__name__)

verifier = "http://192.168.2.115:3000"
callback = "http://192.168.2.115:4000/callback"


@app.route("/test1", methods=['GET'])
def login_test1():
    client_id = "0001"
    url = verifier + "/verifier/app/authorize?client_id=" + client_id + "&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + callback
    return redirect(url)
# https://verifier.wallet-provider.com/verifier/app/authorize?client_id=0001&scope=openid&response_type=id_token&response_mode=query&redirect_uri=https://talao.io

@app.route("/test2", methods=['GET'])
def login_test2():
    client_id = "0002"
    url = verifier + "/verifier/app/authorize?client_id=" + client_id + "&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + callback
    return redirect(url)


@app.route("/callback", methods=['GET'])
def verifier_callback():
    return jsonify(request.args)



# MAIN entry point. Flask http server
if __name__ == '__main__':
    app.run(host="192.168.2.115", port=4000, debug=True)

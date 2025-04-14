import requests
import json
from flask import Flask, render_template_string, request, jsonify
import socket
from flask_qrcode import QRcode

app = Flask(__name__)
qrcode = QRcode(app)


# Adresse de ton serveur MCP REST (à adapter)
BASE_URL = "http://192.168.0.20:3000"

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


def discover_mcp_tools():
    url = f"{BASE_URL}/.well-known/mcp/tools"
    response = requests.get(url)
    response.raise_for_status()
    tools = response.json().get("tools", [])
    
    print("== MCP Tools découverts ==")
    for t in tools:
        print(f"- {t['name']}: {t.get('description', '')}")
    return tools

    
@app.route('/test', methods=['GET', 'POST'])   
def test():
    session_id = request.form["session_id"]
    data = {"session_id": session_id}
    r = requests.post("http://192.168.0.20:3000/tools/check_pid_result", json=data,  timeout=10)
    print("session_id = ", session_id)
    print("Tool MCP 2 = ", r.json())
    return jsonify(r.json())


@app.route('/', methods=['GET', 'POST'])   
def qrcode():
    r = requests.post("http://192.168.0.20:3000/tools/initiate_pid_request", timeout=10)
    result = r.json()
    session_id = result["session_id"]
    url = result['presentation_url']
    print("result = ", result)
    html_string = """<html>
                        <body>
                            <form action="/test" method="POST">
                            <input hidden type="text" name="session_id" value={{session_id}}>

                            <div>
                                <h1>Verifier app for test</h1>
                                <img  src="{{ qrcode(url) }}" width="400"><br>
                            </div>
                            <p>{{url}}</p>
                            
                            <br><br><button  style="width: 200px; height: 50px;" type="submit"><h3>Check</h3></button> 
                            </form> 
                            
                        </body>
                    </html>"""
    return render_template_string(html_string, session_id=session_id, url=url)


    
if __name__ == '__main__':
        
    app.run(host=extract_ip(),
            port=5000,
            debug=True,
            threaded=True)

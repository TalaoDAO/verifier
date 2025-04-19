from openai import OpenAI
import json
from flask import Flask, request, jsonify, render_template, session, Response
from flask_session import Session
import socket
from flask_qrcode import QRcode
import redis
import uuid
from server import tools, initiate_oidc4vp_request, init_app
import os
import message


# Load OpenAI API key
openapi_key = json.load(open("keys.json", "r"))['openai']
  # Load OpenAI API key from a local JSON file
client = OpenAI(
  # Initialize OpenAI client with GPT-4 Turbo model
    api_key=openapi_key,
    timeout=25.0
)

# Utility to extract local IP address for development server
  # Function to get the local IP address of the machine
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
myenv = os.getenv('MYENV')
if myenv == 'aws':
    server = 'https://verifier.wallet-provider.com/'
else:
    server = 'http://' + extract_ip() + ':3000/'


PROMPT = open("system_prompt.txt", "r").read()

# Initialize Flask app
app = Flask(__name__)
qrcode = QRcode(app)
red = redis.Redis(host='localhost', port=6379, db=0)

# Configure Flask sessions to use Redis
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'myapp:'
app.secret_key = 'your_secret_key_here'
Session(app)

MODEL = "gpt-4-turbo"

init_app(app)

@app.errorhandler(500)
def error_500(e):
    message.message("Error 500 on verifier = " + str(e), 'thierry.thevenet@talao.io', str(e))
    return redirect(get_server_url())



  # Simulated backend function to create a customer account (replace with real API call)
def create_customer_account(data):
    # here call an API to create an account
    print("customer account = ", json.dumps(data, indent=4))
    return data



  # Main function to call GPT with chat messages and handle tool calls
def call_gpt(message, session_id):
    print("tools = ",tools)
    print(message)

    # First GPT call to potentially trigger a tool
    response = client.chat.completions.create(
        model=MODEL,
        messages=message,
        tools=tools(),
        tool_choice="auto"
    )

    tool_calls = response.choices[0].message.tool_calls
    # Check if GPT decided to call a tool (e.g. create_customer_account)
    current_chat = "pending"
    account = None
    if tool_calls:
        for tool_call in tool_calls:
            if tool_call.function.name == "create_customer_account":
                args = json.loads(tool_call.function.arguments)
                enriched_args = {}
                verified_claims = json.loads(red.get(session_id + "_verified_claims").decode())
                for key, value in args.items():
                # Build a dictionary with value and whether it was verified
                    enriched_args[key] = {
                        "value": value,
                        "verified": True if verified_claims.get(key, {}).get("verified") == True else False
                    }
                create_customer_account(enriched_args)
                message.append({
                    "role": "function",
                    "name": tool_call.function.name,
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(enriched_args)
                })
                current_chat = "done"
                account = enriched_args

            elif tool_call.function.name == "initiate_pid_request":
                result = initiate_oidc4vp_request(session_id, server)
                if result.get("qr_code_base64"):
                    return result.get("qr_code_base64"), session_id, result.get("request_id"), "pending", account

        # Second GPT call with tool output injected into the conversation
        # Second GPT call after injecting the result of the tool
        second_response = client.chat.completions.create(
            model=MODEL,
            messages=message,
            tools=tools(),
            tool_choice="auto"
        )
        return second_response.choices[0].message.content, session_id, None, current_chat, account

    return response.choices[0].message.content, session_id, None, current_chat, account




# Route to serve the main chat interface
@app.route("/")
def index():
    session_id = str(uuid.uuid1())
    return render_template("chat.html", session_id=session_id)

# Endpoint to handle incoming user messages
  # Endpoint to receive and process user messages from the frontend
@app.route("/send", methods=["POST"])
def send():
    user_message = request.json.get("message")
    session_id = request.json.get("session_id")
    source = request.json.get("source")

    # Reset session if requested
    if any(kw in user_message for kw in ["reset", "clear", "delete"]):
        session.pop("chat", None)
        return jsonify({"reply": "🧼 Conversation history has been cleared. Let's start fresh!"})

    # Initialize session if it's new
    if 'chat' not in session:
        print("Chat session starts now")
        session['chat'] = [
            {
                "role": "system",
                "content": PROMPT
            },
            {
                "role": "user",
                "content": user_message
            }
        ]

    print(session['chat'])
    conversation = session['chat']

    # Append user message with verification context
    if source == "wallet":
        conversation.append({
            "role": "user",
            "content": f"{user_message}\n\nNote: This data was received from a verified digital wallet."
        })
    else:
        conversation.append({
            "role": "user",
            "content": f"{user_message}\n\nNote: This data has not been verified via digital wallet."
        })

    # Call GPT with current conversation
    reply, session_id, request_id, current_chat, account = call_gpt(session['chat'], session_id)
    print("GPT reply = ", reply)

    # Append GPT's reply to session if it's not a base64 image
    if reply:
        if not reply.startswith("data"):
            conversation.append({"role": "assistant", "content": reply})
    else:
        reply = "👋 Bye! Your account has been created"

    session['chat'] = conversation
    return jsonify({
        "status": current_chat,
        "reply": reply,
        "request_id": request_id,
        "session_id": session_id,
        "account": account
    })




# Stream endpoint using Server-Sent Events for frontend updates
  # Server-Sent Events endpoint to stream updates to the frontend
@app.route("/chatbot_stream", methods=["GET"], defaults={'red': red})
def chatbot_stream(red):
    def login_event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('chatbot')
        for message in pubsub.listen():
            if message['type'] == 'message':
                yield 'data: %s\n\n' % message['data'].decode()

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no"
    }
    return Response(login_event_stream(red), headers=headers)



# Run the Flask application
if __name__ == '__main__':
  # Run the Flask application on the local IP
    app.run(host=extract_ip(), port=3000, debug=True, threaded=True)

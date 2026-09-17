from flask import Flask, send_from_directory, request
from flask_socketio import SocketIO
import socket
import threading

app = Flask(__name__, static_folder="web")
socketio = SocketIO(app, cors_allowed_origins="*")

TCP_HOST = "127.0.0.1"
TCP_PORT = 5000

# username -> TCP socket
web_clients = {}

# username -> browser socket ID
browser_ids = {}


# ==========================================
# SERVE WEBSITE
# ==========================================


@app.route("/")
def index():
    return send_from_directory("web", "index.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("web", path)


# ==========================================
# RECEIVE FROM TCP SERVER
# ==========================================


def receive_from_tcp(username, tcp_client, sid):

    while True:

        try:

            message = tcp_client.recv(4096).decode()

            if not message:
                break

            print("TCP ->", username, ":", message)

            # ==================================
            # USER LIST
            # ==================================

            if message.startswith("USERS|"):

                parts = message.split("|")

                users = parts[1:]

                print("Sending users to browser:", users)

                socketio.emit("users", {"users": users}, to=sid)

            # ==================================
            # PRIVATE MESSAGE
            # ==================================

            elif message.startswith("MESSAGE|"):

                parts = message.split("|", 2)

                if len(parts) >= 3:

                    sender = parts[1]
                    text = parts[2]

                    # Send acknowledgement
                    # back to TCP server

                    tcp_client.send(("/ack|" + sender + "|" + username).encode())

                    socketio.emit(
                        "message", {"username": sender, "message": text}, to=sid
                    )

            # ==================================
            # MESSAGE SENT
            # ==================================

            elif message == "SENT":

                socketio.emit("sent", {"message": "Message sent"}, to=sid)

            # ==================================
            # MESSAGE DELIVERED
            # ==================================

            elif message.startswith("DELIVERED|"):

                parts = message.split("|", 1)

                if len(parts) == 2:

                    receiver = parts[1]

                    socketio.emit("delivered", {"receiver": receiver}, to=sid)

            # ==================================
            # GROUP MESSAGE
            # ==================================

            elif message.startswith("GROUP|"):

                parts = message.split("|", 3)

                if len(parts) >= 4:

                    group_name = parts[1]
                    sender = parts[2]
                    text = parts[3]

                    socketio.emit(
                        "group_message",
                        {"group": group_name, "username": sender, "message": text},
                        to=sid,
                    )

            # ==================================
            # OTHER SERVER MESSAGE
            # ==================================

            else:

                socketio.emit("status", {"text": message}, to=sid)

        except Exception as e:

            print("TCP receive error for", username, ":", e)

            break

    # ==========================================
    # CLEANUP
    # ==========================================

    if username in web_clients:

        del web_clients[username]

    if username in browser_ids:

        del browser_ids[username]

    try:
        tcp_client.close()
    except:
        pass


# ==========================================
# BROWSER LOGIN
# ==========================================


@socketio.on("login")
def login(data):

    username = data.get("username", "").strip()

    sid = request.sid

    print("Browser login:", username)

    if not username:

        socketio.emit("login_error", {"message": "Username is required"}, to=sid)

        return

    # ==========================================
    # PREVENT DUPLICATE WEB LOGIN
    # ==========================================

    if username in web_clients:

        socketio.emit("login_error", {"message": "Username already logged in"}, to=sid)

        return

    try:

        # ======================================
        # CONNECT TO TCP SERVER
        # ======================================

        tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        tcp_client.connect((TCP_HOST, TCP_PORT))

        # ======================================
        # SEND USERNAME
        # ======================================

        tcp_client.send(username.encode())

        # ======================================
        # RECEIVE WELCOME
        # ======================================

        response = tcp_client.recv(4096).decode()

        print("TCP response:", response)

        # ======================================
        # CHECK DUPLICATE USERNAME
        # ======================================

        if response == "Username already in use!":

            tcp_client.close()

            socketio.emit(
                "login_error", {"message": "Username already in use!"}, to=sid
            )

            return

        # ======================================
        # STORE CONNECTION
        # ======================================

        web_clients[username] = tcp_client

        browser_ids[username] = sid

        # ======================================
        # TELL BROWSER LOGIN SUCCESS
        # ======================================

        socketio.emit("login_success", {"message": response}, to=sid)

        # ======================================
        # START TCP RECEIVER THREAD
        # ======================================

        thread = threading.Thread(
            target=receive_from_tcp, args=(username, tcp_client, sid)
        )

        thread.daemon = True

        thread.start()

        print(username, "connected successfully")

    except Exception as e:

        print("Login error:", e)

        socketio.emit(
            "login_error", {"message": "Could not connect to chat server"}, to=sid
        )


# ==========================================
# SEND CHAT MESSAGE
# ==========================================


@socketio.on("chat_message")
def chat_message(data):

    username = data.get("username")
    receiver = data.get("receiver")
    message = data.get("message")

    print("CHAT:", username, "->", receiver, ":", message)

    if username not in web_clients:

        socketio.emit("status", {"text": "You are not connected."}, to=request.sid)

        return

    tcp_client = web_clients[username]

    command = "/msg " + receiver + " " + message

    try:

        tcp_client.send(command.encode())

    except Exception as e:

        print("Send error:", e)


# ==========================================
# BROWSER DISCONNECT
# ==========================================


@socketio.on("disconnect")
def disconnect():

    sid = request.sid

    print("Browser disconnected:", sid)

    # Find username belonging to browser

    username_to_remove = None

    for username, browser_sid in browser_ids.items():

        if browser_sid == sid:

            username_to_remove = username

            break

    if username_to_remove:

        print("Removing:", username_to_remove)

        if username_to_remove in web_clients:

            try:

                web_clients[username_to_remove].send("/exit".encode())

            except:
                pass

            try:

                web_clients[username_to_remove].close()

            except:
                pass

            del web_clients[username_to_remove]

        if username_to_remove in browser_ids:

            del browser_ids[username_to_remove]


# ==========================================
# START WEB SERVER
# ==========================================

if __name__ == "__main__":

    print("================================")
    print("       SECURE CHAT WEB SERVER")
    print("================================")
    print("Web server started on port 8000")
    print("Open: http://127.0.0.1:8000")
    print()

    socketio.run(
        app, host="0.0.0.0", port=8000, debug=False, allow_unsafe_werkzeug=True
    )

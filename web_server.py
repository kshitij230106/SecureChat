import socket
import threading
import base64

from flask import Flask, render_template, request
from flask_socketio import SocketIO

import database
import key_manager
import encryption

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# =========================================================
# CONFIGURATION
# =========================================================

TCP_HOST = "127.0.0.1"
TCP_PORT = 5000

WEB_HOST = "127.0.0.1"
WEB_PORT = 8000


# =========================================================
# FLASK
# =========================================================

app = Flask(__name__, static_folder="web", template_folder="web")

socketio = SocketIO(app, cors_allowed_origins="*")


# =========================================================
# GLOBAL STATE
# =========================================================

web_clients = {}
browser_ids = {}

clients_lock = threading.Lock()


# =========================================================
# ROUTES
# =========================================================


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/chat")
def chat_page():
    return render_template("chat.html")


@app.route("/<path:path>")
def static_files(path):
    return app.send_static_file(path)


# =========================================================
# TCP SEND
# =========================================================


def tcp_send(client, message):

    try:

        client.sendall((message + "\n").encode())

        return True

    except Exception as e:

        print("[TCP SEND ERROR]", e)

        return False


# =========================================================
# TCP RECEIVE
# =========================================================


def tcp_receive_line(client, buffer):

    try:

        while "\n" not in buffer:

            data = client.recv(8192)

            if not data:

                return None, buffer

            buffer += data.decode()

        line, buffer = buffer.split("\n", 1)

        return line.strip(), buffer

    except Exception as e:

        print("[TCP RECEIVE ERROR]", e)

        return None, buffer


# =========================================================
# EMIT TO CURRENT BROWSER
# =========================================================


def emit_to_user(username, event, data=None):

    with clients_lock:

        sid = browser_ids.get(username)

    if not sid:

        print("[NO BROWSER]", username, event)

        return

    try:

        socketio.emit(event, data, to=sid)

    except Exception as e:

        print("[SOCKET EMIT ERROR]", username, e)


# =========================================================
# GET USERNAME FROM SOCKET ID
# =========================================================


def get_username_from_sid(sid):

    with clients_lock:

        for username, browser_sid in browser_ids.items():

            if browser_sid == sid:

                return username

    return None


# =========================================================
# AUTHENTICATION
# =========================================================


def authenticate_web_user(tcp_client, choice, username, password):

    try:

        # AUTH REQUEST

        response, buffer = tcp_receive_line(tcp_client, "")

        if response != "AUTH_REQUEST":

            print("[AUTH ERROR]", response)

            return False

        # LOGIN / REGISTER

        tcp_send(tcp_client, choice)

        # USERNAME

        response, buffer = tcp_receive_line(tcp_client, buffer)

        if response != "USERNAME":

            return False

        tcp_send(tcp_client, username)

        # PASSWORD

        response, buffer = tcp_receive_line(tcp_client, buffer)

        if response != "PASSWORD":

            return False

        tcp_send(tcp_client, password)

        # RESULT

        response, buffer = tcp_receive_line(tcp_client, buffer)

        print("[AUTH]", response)

        if not response:

            return False

        if response.startswith("AUTH_FAILED|"):

            return False

        if not response.startswith("AUTH_SUCCESS|"):

            return False

        # READY REQUEST

        response, buffer = tcp_receive_line(tcp_client, buffer)

        print("[AUTH]", response)

        if response != "READY_REQUEST":

            return False

        tcp_send(tcp_client, "READY")

        # READY OK

        response, buffer = tcp_receive_line(tcp_client, buffer)

        print("[AUTH]", response)

        if response != "READY_OK":

            return False

        return True

    except Exception as e:

        print("[AUTH ERROR]", e)

        return False


# =========================================================
# CRYPTOGRAPHY
# =========================================================


def ensure_user_keys(username):

    try:

        key_manager.generate_keys(username)

        print("[KEYS READY]", username)

        return True

    except Exception as e:

        print("[KEY ERROR]", username, e)

        return False


# =========================================================
# REGISTER PUBLIC KEY WITH TCP SERVER
# =========================================================


def register_public_key(username, tcp_client):

    try:

        public_key = key_manager.get_public_key_text(username)

        command = "PUBLIC_KEY|" + username + "|" + public_key

        tcp_send(tcp_client, command)

        print("[PUBLIC KEY REGISTERED]", username)

        return True

    except Exception as e:

        print("[PUBLIC KEY ERROR]", e)

        return False


# =========================================================
# ENCRYPT MESSAGE
# =========================================================


def encrypt_for_user(sender, receiver, text):

    try:

        # -------------------------------------------------
        # GET RECEIVER PUBLIC KEY
        # -------------------------------------------------

        public_key_text = database.get_public_key(receiver)

        if not public_key_text:

            print("[ENCRYPT ERROR] Public key not found:", receiver)

            return None

        # -------------------------------------------------
        # LOAD RSA PUBLIC KEY
        # -------------------------------------------------

        public_key = key_manager.public_key_from_text(public_key_text)

        # -------------------------------------------------
        # GENERATE FERNET KEY
        # -------------------------------------------------

        symmetric_key = encryption.generate_key()

        # -------------------------------------------------
        # FERNET ENCRYPT
        # -------------------------------------------------

        encrypted_message = encryption.encrypt_message(text, symmetric_key)

        # -------------------------------------------------
        # RSA-OAEP ENCRYPT FERNET KEY
        # -------------------------------------------------

        encrypted_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # -------------------------------------------------
        # BASE64
        # -------------------------------------------------

        encrypted_key_text = base64.b64encode(encrypted_key).decode()

        # -------------------------------------------------
        # COMBINE
        # -------------------------------------------------

        encrypted_data = encrypted_key_text + "||" + encrypted_message

        return encrypted_data

    except Exception as e:

        print("[ENCRYPT ERROR]", sender, "->", receiver, e)

        return None


# =========================================================
# DECRYPT MESSAGE
# =========================================================


def decrypt_message_for_user(username, encrypted_data):

    try:

        # -------------------------------------------------
        # SPLIT RSA + FERNET
        # -------------------------------------------------

        encrypted_key, encrypted_message = encrypted_data.split("||", 1)

        # -------------------------------------------------
        # LOAD PRIVATE KEY
        # -------------------------------------------------

        private_key = key_manager.load_private_key(username)

        # -------------------------------------------------
        # BASE64 DECODE RSA KEY
        # -------------------------------------------------

        encrypted_key_bytes = base64.b64decode(encrypted_key)

        # -------------------------------------------------
        # RSA DECRYPT
        # -------------------------------------------------

        symmetric_key = private_key.decrypt(
            encrypted_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # -------------------------------------------------
        # FERNET DECRYPT
        # -------------------------------------------------

        text = encryption.decrypt_message(encrypted_message, symmetric_key)

        return text

    except Exception as e:

        print("[DECRYPT ERROR]", username, e)

        return None


# =========================================================
# TCP RECEIVE THREAD
# =========================================================


def receive_from_tcp(username, tcp_client):

    buffer = ""

    print("[TCP RECEIVER STARTED]", username)

    try:

        while True:

            message, buffer = tcp_receive_line(tcp_client, buffer)

            if message is None:

                break

            if not message:

                continue

            print("[TCP -> WEB]", username, ":", message)

            # =================================================
            # USERS
            # =================================================

            if message.startswith("USERS|"):

                users = message.split("|", 1)[1]

                emit_to_user(
                    username, "users", {"users": users.split("|") if users else []}
                )

            # =================================================
            # GROUPS
            # =================================================

            elif message.startswith("GROUPS|"):

                groups = message.split("|", 1)[1]

                emit_to_user(
                    username, "groups", {"groups": groups.split("|") if groups else []}
                )

            # =================================================
            # PUBLIC KEY
            # =================================================

            elif message.startswith("PUBLIC_KEY|"):

                parts = message.split("|", 2)

                if len(parts) == 3:

                    target = parts[1]
                    public_key = parts[2]

                    emit_to_user(
                        username, "public_key", {"username": target, "key": public_key}
                    )

            # =================================================
            # KEY SUCCESS
            # =================================================

            elif message.startswith("KEY_SUCCESS|"):

                emit_to_user(
                    username, "key_success", {"message": message.split("|", 1)[1]}
                )

            # =================================================
            # PRIVATE MESSAGE
            # =================================================

            elif message.startswith("MESSAGE|"):

                parts = message.split("|", 3)

                if len(parts) == 4:

                    sender = parts[1]

                    message_id = parts[2]

                    encrypted_data = parts[3]

                    decrypted_text = decrypt_message_for_user(username, encrypted_data)

                    if decrypted_text is not None:

                        emit_to_user(
                            username,
                            "message",
                            {
                                "sender": sender,
                                "message_id": message_id,
                                "message": decrypted_text,
                            },
                        )

                        # ACK

                        if message_id != "0":

                            tcp_send(tcp_client, "/ack|" + message_id)

                    else:

                        emit_to_user(
                            username, "error", {"message": "Could not decrypt message"}
                        )

            # =================================================
            # HISTORY
            # =================================================

            elif message.startswith("HISTORY|"):

                history_text = message.split("|", 1)[1]

                history = []

                if history_text:

                    records = history_text.split(";;")

                    for record in records:

                        try:

                            parts = record.split(" | ", 2)

                            if len(parts) != 3:

                                continue

                            timestamp = parts[0]

                            users_part = parts[1]

                            encrypted_data = parts[2]

                            user_parts = users_part.split(" -> ")

                            if len(user_parts) != 2:

                                continue

                            sender = user_parts[0]

                            receiver = user_parts[1]

                            # ---------------------------------
                            # Decrypt
                            # ---------------------------------

                            decrypted_text = decrypt_message_for_user(
                                username, encrypted_data
                            )

                            if decrypted_text is None:
                                continue

                            history.append(
                                {
                                    "sender": sender,
                                    "receiver": receiver,
                                    "message": decrypted_text,
                                    "timestamp": timestamp,
                                }
                            )

                        except Exception as e:

                            print("[HISTORY RECORD ERROR]", e)

                emit_to_user(username, "history", {"history": history})

            # =================================================
            # GROUP MESSAGE
            # =================================================

            elif message.startswith("GROUP|"):

                parts = message.split("|", 3)

                if len(parts) >= 4:

                    group_name = parts[1]

                    sender = parts[2]

                    text = parts[3]

                    emit_to_user(
                        username,
                        "group_message",
                        {"group": group_name, "sender": sender, "message": text},
                    )

                elif len(parts) == 3:

                    group_name = parts[1]

                    text = parts[2]

                    emit_to_user(
                        username,
                        "group_message",
                        {"group": group_name, "sender": "", "message": text},
                    )

            # =================================================
            # SENT
            # =================================================

            elif message == "SENT":

                emit_to_user(username, "sent", {"success": True})

            # =================================================
            # SERVER
            # =================================================

            elif message.startswith("SERVER|"):

                emit_to_user(username, "server", {"message": message.split("|", 1)[1]})

            # =================================================
            # GROUP CREATED
            # =================================================

            elif message.startswith("GROUP_CREATED|"):

                group_name = message.split("|", 1)[1]

                emit_to_user(username, "group_created", {"group": group_name})

            # =================================================
            # JOINED
            # =================================================

            elif message.startswith("JOINED|"):

                group_name = message.split("|", 1)[1]

                emit_to_user(username, "joined", {"group": group_name})

            # =================================================
            # ERROR
            # =================================================

            elif message.startswith("ERROR|"):

                error_message = message.split("|", 1)[1]

                emit_to_user(username, "error", {"message": error_message})

            # =================================================
            # SERVER SHUTDOWN
            # =================================================

            elif message == "SERVER_SHUTDOWN":

                emit_to_user(username, "server_shutdown", {})

                break

    except Exception as e:

        print("[TCP RECEIVER ERROR]", username, e)

    finally:

        print("[TCP RECEIVER CLOSED]", username)

        with clients_lock:

            if web_clients.get(username) is tcp_client:

                web_clients.pop(username, None)

                browser_ids.pop(username, None)

        try:

            tcp_client.close()

        except Exception:

            pass


# =========================================================
# SOCKET LOGIN
# =========================================================


@socketio.on("login")
def login(data):

    sid = request.sid

    username = data.get("username", "").strip()

    password = data.get("password", "")

    print("[WEB LOGIN]", username)

    if not username or not password:

        socketio.emit(
            "login_error", {"message": "Username and password required"}, to=sid
        )

        return

    with clients_lock:

        if username in web_clients:

            socketio.emit("login_error", {"message": "User already online"}, to=sid)

            return

    # =========================================================
    # CREATE TCP CONNECTION
    # =========================================================

    try:

        tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        tcp_client.connect((TCP_HOST, TCP_PORT))

    except Exception as e:

        print("[TCP CONNECTION ERROR]", e)

        socketio.emit(
            "login_error", {"message": "Could not connect to chat server"}, to=sid
        )

        return

    # =========================================================
    # AUTH
    # =========================================================

    success = authenticate_web_user(tcp_client, "LOGIN", username, password)

    if not success:

        try:

            tcp_client.close()

        except Exception:

            pass

        socketio.emit(
            "login_error", {"message": "Invalid username or password"}, to=sid
        )

        return

    # =========================================================
    # GENERATE / LOAD KEYS
    # =========================================================

    if not ensure_user_keys(username):

        tcp_client.close()

        socketio.emit(
            "login_error", {"message": "Could not prepare encryption keys"}, to=sid
        )

        return

    # =========================================================
    # REGISTER PUBLIC KEY
    # =========================================================

    if not register_public_key(username, tcp_client):

        tcp_client.close()

        socketio.emit(
            "login_error", {"message": "Could not register public key"}, to=sid
        )

        return

    # =========================================================
    # SAVE CONNECTION
    # =========================================================

    with clients_lock:

        web_clients[username] = tcp_client

        browser_ids[username] = sid

    print("[LOGIN SUCCESS]", username)

    socketio.emit("login_success", {"username": username}, to=sid)

    # =========================================================
    # START RECEIVER
    # =========================================================

    receiver_thread = threading.Thread(
        target=receive_from_tcp, args=(username, tcp_client), daemon=True
    )

    receiver_thread.start()


# =========================================================
# REGISTER
# =========================================================


@socketio.on("register")
def register(data):

    sid = request.sid

    username = data.get("username", "").strip()

    password = data.get("password", "")

    print("[WEB REGISTER]", username)

    if not username or not password:

        socketio.emit(
            "register_error", {"message": "Username and password required"}, to=sid
        )

        return

    try:

        tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        tcp_client.connect((TCP_HOST, TCP_PORT))

    except Exception as e:

        print("[REGISTER TCP ERROR]", e)

        socketio.emit(
            "register_error", {"message": "Could not connect to server"}, to=sid
        )

        return

    success = authenticate_web_user(tcp_client, "REGISTER", username, password)

    if success:

        try:

            tcp_client.close()

        except Exception:

            pass

        socketio.emit(
            "register_success",
            {"message": "Registration successful. Please login."},
            to=sid,
        )

    else:

        try:

            tcp_client.close()

        except Exception:

            pass

        socketio.emit(
            "register_error",
            {"message": "Registration failed. Username may already exist."},
            to=sid,
        )


# =========================================================
# ATTACH CHAT BROWSER
# =========================================================


@socketio.on("attach")
def attach(data):

    sid = request.sid

    username = data.get("username", "").strip()

    print("[ATTACH REQUEST]", username, sid)

    if not username:

        socketio.emit("attach_error", {"message": "Username missing"}, to=sid)

        return

    with clients_lock:

        if username not in web_clients:

            print("[ATTACH FAILED]", username)

            socketio.emit(
                "attach_error", {"message": "TCP connection not found"}, to=sid
            )

            return

        browser_ids[username] = sid

    print("[ATTACHED]", username, "->", sid)

    socketio.emit("attach_success", {"username": username}, to=sid)

    tcp_client = web_clients.get(username)

    if tcp_client:

        tcp_send(tcp_client, "/users")

        tcp_send(tcp_client, "/groups")


# =========================================================
# CHAT MESSAGE
# =========================================================


@socketio.on("chat_message")
def chat_message(data):

    sid = request.sid

    username = get_username_from_sid(sid)

    if not username:

        return

    receiver = data.get("receiver", "").strip()

    text = data.get("message", "")

    if not receiver or not text:

        return

    print("[CHAT]", username, "->", receiver, ":", text)

    tcp_client = web_clients.get(username)

    if not tcp_client:

        socketio.emit("error", {"message": "TCP connection unavailable"}, to=sid)

        return

    # =========================================================
    # ENCRYPT
    # =========================================================

    encrypted_data = encrypt_for_user(username, receiver, text)

    if not encrypted_data:

        socketio.emit(
            "error",
            {
                "message": "Could not encrypt message. Recipient public key may be unavailable."
            },
            to=sid,
        )

        return

    # =========================================================
    # SEND ENCRYPTED MESSAGE
    # =========================================================

    command = "/encrypted|" + receiver + "|" + encrypted_data

    if tcp_send(tcp_client, command):

        print("[ENCRYPTED MESSAGE SENT]", username, "->", receiver)

    else:

        socketio.emit("error", {"message": "Could not send message"}, to=sid)


# =========================================================
# GET USERS
# =========================================================


@socketio.on("get_users")
def get_users():

    sid = request.sid

    username = get_username_from_sid(sid)

    if not username:

        return

    tcp_client = web_clients.get(username)

    if tcp_client:

        tcp_send(tcp_client, "/users")


# =========================================================
# GET GROUPS
# =========================================================


@socketio.on("get_groups")
def get_groups():

    sid = request.sid

    username = get_username_from_sid(sid)

    if not username:

        return

    tcp_client = web_clients.get(username)

    if tcp_client:

        tcp_send(tcp_client, "/groups")


# =========================================================
# GET HISTORY
# =========================================================


@socketio.on("get_history")
def get_history(data):

    sid = request.sid

    username = get_username_from_sid(sid)

    if not username:

        return

    target = data.get("username", "").strip()

    if not target:

        return

    tcp_client = web_clients.get(username)

    if tcp_client:

        tcp_send(tcp_client, "/history " + target)


# =========================================================
# GET PUBLIC KEY
# =========================================================


@socketio.on("get_public_key")
def get_public_key(data):

    sid = request.sid

    username = get_username_from_sid(sid)

    if not username:

        return

    target = data.get("username", "").strip()

    if not target:

        return

    tcp_client = web_clients.get(username)

    if tcp_client:

        tcp_send(tcp_client, "/key " + target)


# =========================================================
# CREATE GROUP
# =========================================================


@socketio.on("create_group")
def create_group(data):

    sid = request.sid

    username = get_username_from_sid(sid)

    if not username:

        return

    groupname = data.get("groupname", "").strip()

    if not groupname:

        return

    tcp_client = web_clients.get(username)

    if tcp_client:

        tcp_send(tcp_client, "/create " + groupname)


# =========================================================
# JOIN GROUP
# =========================================================


@socketio.on("join_group")
def join_group(data):

    sid = request.sid

    username = get_username_from_sid(sid)

    if not username:

        return

    groupname = data.get("groupname", "").strip()

    if not groupname:

        return

    tcp_client = web_clients.get(username)

    if tcp_client:

        tcp_send(tcp_client, "/join " + groupname)


# =========================================================
# GROUP MESSAGE
# =========================================================


@socketio.on("group_message")
def group_message(data):

    sid = request.sid

    username = get_username_from_sid(sid)

    if not username:

        return

    groupname = data.get("groupname", "").strip()

    text = data.get("message", "")

    if not groupname or not text:

        return

    tcp_client = web_clients.get(username)

    if not tcp_client:

        return

    command = "/groupmsg " + groupname + " " + text

    tcp_send(tcp_client, command)


# =========================================================
# GROUP HISTORY
# =========================================================


@socketio.on("get_group_history")
def get_group_history(data):

    sid = request.sid

    username = get_username_from_sid(sid)

    if not username:

        return

    groupname = data.get("groupname", "").strip()

    if not groupname:

        return

    tcp_client = web_clients.get(username)

    if tcp_client:

        tcp_send(tcp_client, "/grouphistory " + groupname)


# =========================================================
# LOGOUT
# =========================================================


@socketio.on("logout")
def logout():

    sid = request.sid

    username = get_username_from_sid(sid)

    if not username:

        return

    print("[WEB LOGOUT]", username)

    with clients_lock:

        tcp_client = web_clients.get(username)

        web_clients.pop(username, None)

        browser_ids.pop(username, None)

    if tcp_client:

        tcp_send(tcp_client, "/exit")

        try:

            tcp_client.close()

        except Exception:

            pass


# =========================================================
# BROWSER DISCONNECT
# =========================================================


@socketio.on("disconnect")
def disconnect():

    sid = request.sid

    print("[BROWSER DISCONNECTED]", sid)

    username = None

    with clients_lock:

        for user, browser_sid in browser_ids.items():

            if browser_sid == sid:

                username = user

                break

        if not username:

            return

        if browser_ids.get(username) == sid:

            browser_ids.pop(username, None)

            print("[BROWSER DETACHED]", username)


# =========================================================
# START
# =========================================================

if __name__ == "__main__":

    print("====================================")

    print("       SECURE CHAT WEB SERVER")

    print("====================================")

    print("Web server:", f"http://{WEB_HOST}:{WEB_PORT}")

    print("TCP server:", f"{TCP_HOST}:{TCP_PORT}")

    print("Encryption: ENABLED 🔐")

    print("====================================")

    socketio.run(
        app, host=WEB_HOST, port=WEB_PORT, debug=True, allow_unsafe_werkzeug=True
    )

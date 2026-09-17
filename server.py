import socket
import threading
import database

# =========================================================
# CONFIGURATION
# =========================================================

HOST = "0.0.0.0"
PORT = 5000


# =========================================================
# GLOBAL STATE
# =========================================================

clients = {}
public_keys = {}

clients_lock = threading.Lock()
keys_lock = threading.Lock()

server = None
running = True


# =========================================================
# DATABASE
# =========================================================

database.create_tables()


# =========================================================
# SEND MESSAGE
# Newline-delimited protocol
# =========================================================


def send_message(client, message):
    try:
        client.sendall((message + "\n").encode())
        return True
    except Exception:
        return False


# =========================================================
# RECEIVE LINE
# Handles TCP packet merging/splitting
# =========================================================


def receive_line(client, buffer):
    while "\n" not in buffer:
        data = client.recv(4096)

        if not data:
            return None, buffer

        buffer += data.decode()

    line, buffer = buffer.split("\n", 1)

    return line.strip(), buffer


# =========================================================
# BROADCAST
# =========================================================


def broadcast(message, exclude=None):

    with clients_lock:
        current_clients = list(clients.items())

    for username, client in current_clients:

        if username == exclude:
            continue

        send_message(client, message)


# =========================================================
# SEND ONLINE USER LIST
# =========================================================


def send_user_list():

    with clients_lock:
        users = list(clients.keys())

    message = "USERS|" + "|".join(users)

    broadcast(message)


# =========================================================
# GET GROUP NAMES
#
# Handles both possible database return formats:
#
# ["friends", "TestGroup"]
#
# OR
#
# [(1, "friends", "Rahul", ...), ...]
# =========================================================


def get_group_names():

    try:
        group_list = database.get_groups()
    except Exception as e:
        print("[GROUP ERROR]", e)
        return []

    names = []

    for group in group_list:

        if isinstance(group, str):

            names.append(group)

        elif isinstance(group, (tuple, list)):

            if len(group) >= 2:
                names.append(str(group[1]))

    return names


# =========================================================
# SEND GROUP LIST
# =========================================================


def send_group_list(client):

    names = get_group_names()

    if names:
        message = "GROUPS|" + "|".join(names)
    else:
        message = "GROUPS|"

    send_message(client, message)


# =========================================================
# AUTHENTICATION
# =========================================================


def authenticate(client):

    buffer = ""

    try:

        # -------------------------------------------------
        # ASK LOGIN / REGISTER
        # -------------------------------------------------

        send_message(client, "AUTH_REQUEST")

        choice, buffer = receive_line(client, buffer)

        if choice is None:
            return None, buffer

        choice = choice.strip().upper()

        if choice not in ["LOGIN", "REGISTER"]:

            send_message(client, "AUTH_FAILED|Invalid choice")

            return None, buffer

        # -------------------------------------------------
        # ASK USERNAME
        # -------------------------------------------------

        send_message(client, "USERNAME")

        username, buffer = receive_line(client, buffer)

        if username is None:
            return None, buffer

        username = username.strip()

        if not username:

            send_message(client, "AUTH_FAILED|Invalid username")

            return None, buffer

        # -------------------------------------------------
        # ASK PASSWORD
        # -------------------------------------------------

        send_message(client, "PASSWORD")

        password, buffer = receive_line(client, buffer)

        if password is None:
            return None, buffer

        password = password.strip()

        if not password:

            send_message(client, "AUTH_FAILED|Invalid password")

            return None, buffer

        # =================================================
        # REGISTER
        # =================================================

        if choice == "REGISTER":

            if database.create_user(username, password):

                send_message(client, "AUTH_SUCCESS|Registration successful")

                print(f"[REGISTERED] {username}")

            else:

                send_message(client, "AUTH_FAILED|Username already exists")

            return None, buffer

        # =================================================
        # LOGIN
        # =================================================

        if not database.verify_login(username, password):

            send_message(client, "AUTH_FAILED|Invalid username or password")

            print(f"[LOGIN FAILED] {username}")

            return None, buffer

        # -------------------------------------------------
        # PREVENT DUPLICATE LOGIN
        # -------------------------------------------------

        with clients_lock:

            if username in clients:

                send_message(client, "AUTH_FAILED|User already online")

                print(f"[LOGIN FAILED] {username} already online")

                return None, buffer

            clients[username] = client

        # -------------------------------------------------
        # LOGIN SUCCESS
        # -------------------------------------------------

        send_message(client, f"AUTH_SUCCESS|Welcome {username}")

        print(f"[LOGIN SUCCESS] {username}")

        # -------------------------------------------------
        # READY HANDSHAKE
        # -------------------------------------------------

        send_message(client, "READY_REQUEST")

        ready, buffer = receive_line(client, buffer)

        if ready is None:
            return None, buffer

        if ready != "READY":

            with clients_lock:
                clients.pop(username, None)

            send_message(client, "AUTH_FAILED|Handshake failed")

            return None, buffer

        # -------------------------------------------------
        # READY OK
        # -------------------------------------------------

        send_message(client, "READY_OK")

        return username, buffer

    except Exception as e:

        print("[AUTH ERROR]", e)

        return None, buffer


# =========================================================
# SEND OFFLINE MESSAGES
# =========================================================


def send_pending_messages(username, client):

    try:

        messages = database.get_pending_messages(username)

        for message_id, sender, encrypted_message in messages:

            send_message(client, f"MESSAGE|{sender}|{message_id}|{encrypted_message}")

            print(f"[OFFLINE MESSAGE] {sender} -> {username}")

            # Keep existing behavior
            database.update_message_status(message_id, "delivered")

    except Exception as e:

        print("[OFFLINE MESSAGE ERROR]", e)


# =========================================================
# PRIVATE ENCRYPTED MESSAGE
# =========================================================


def handle_private_message(username, command):

    try:

        parts = command.split("|", 2)

        if len(parts) != 3:

            return "ERROR|Invalid encrypted message format"

        receiver = parts[1].strip()
        encrypted_message = parts[2]

        # -------------------------------------------------
        # CHECK RECEIVER
        # -------------------------------------------------

        if not database.get_user(receiver):

            return "ERROR|User does not exist"

        # -------------------------------------------------
        # PREVENT SELF MESSAGE
        # -------------------------------------------------

        if receiver == username:

            return "ERROR|Cannot message yourself"

        # -------------------------------------------------
        # SAVE ENCRYPTED MESSAGE
        # Server NEVER decrypts this message
        # -------------------------------------------------

        message_id = database.save_message(
            username, receiver, encrypted_message, "sent"
        )

        # -------------------------------------------------
        # CHECK IF RECEIVER ONLINE
        # -------------------------------------------------

        with clients_lock:

            receiver_client = clients.get(receiver)

        # -------------------------------------------------
        # ONLINE
        # -------------------------------------------------

        if receiver_client:

            success = send_message(
                receiver_client, f"MESSAGE|{username}|{message_id}|{encrypted_message}"
            )

            if success:

                database.update_message_status(message_id, "delivered")

                print(f"[ENCRYPTED] {username} -> {receiver}")

            else:

                print(f"[DELIVERY FAILED] {username} -> {receiver}")

        # -------------------------------------------------
        # OFFLINE
        # -------------------------------------------------

        else:

            print(f"[OFFLINE ENCRYPTED] " f"{username} -> {receiver}")

        return "SENT"

    except Exception as e:

        print("[PRIVATE MESSAGE ERROR]", e)

        return "ERROR|Could not send encrypted message"


# =========================================================
# GROUP MESSAGE
# =========================================================


def handle_group_message(username, command):

    try:

        parts = command.split("|", 2)

        if len(parts) != 3:

            return "ERROR|Invalid group message"

        group_name = parts[1].strip()
        message = parts[2]

        # -------------------------------------------------
        # CHECK GROUP
        # -------------------------------------------------

        group = database.get_group(group_name)

        if not group:

            return "ERROR|Group does not exist"

        # -------------------------------------------------
        # GET MEMBERS
        # -------------------------------------------------

        members = database.get_group_members(group_name)

        # -------------------------------------------------
        # CHECK MEMBERSHIP
        # -------------------------------------------------

        if username not in members:

            return "ERROR|You are not a member of this group"

        # -------------------------------------------------
        # SAVE GROUP MESSAGE
        # -------------------------------------------------

        database.save_group_message(group_name, username, message)

        # -------------------------------------------------
        # COPY ONLINE CLIENTS
        # -------------------------------------------------

        with clients_lock:

            current_clients = dict(clients)

        # -------------------------------------------------
        # SEND TO MEMBERS
        # -------------------------------------------------

        for member in members:

            if member == username:
                continue

            if member in current_clients:

                send_message(
                    current_clients[member],
                    f"GROUP|{group_name}|" f"{username}: {message}",
                )

        print(f"[GROUP] " f"{username} -> {group_name}: {message}")

        return "SENT"

    except Exception as e:

        print("[GROUP MESSAGE ERROR]", e)

        return "ERROR|Could not send group message"


# =========================================================
# CLIENT HANDLER
# =========================================================


def handle_client(client, address):

    username = None
    buffer = ""

    try:

        # =================================================
        # AUTHENTICATION
        # =================================================

        username, buffer = authenticate(client)

        if not username:

            try:
                client.close()
            except Exception:
                pass

            return

        print(f"[CONNECTED] {username} " f"from {address}")

        # =================================================
        # NOTIFY OTHER USERS
        # =================================================

        broadcast(f"SERVER|{username} joined the chat", exclude=username)

        send_user_list()

        # =================================================
        # SEND GROUP LIST
        # =================================================

        send_group_list(client)

        # =================================================
        # SEND OFFLINE MESSAGES
        # =================================================

        send_pending_messages(username, client)

        # =================================================
        # MAIN CLIENT LOOP
        # =================================================

        while running:

            command, buffer = receive_line(client, buffer)

            if command is None:
                break

            if not command:
                continue

            # =================================================
            # PUBLIC KEY REGISTRATION
            # =================================================

            if command.startswith("PUBLIC_KEY|"):

                parts = command.split("|", 2)

                # -------------------------------------------------
                # New format:
                # PUBLIC_KEY|username|public_key
                # -------------------------------------------------

                if len(parts) == 3:

                    key_username = parts[1]
                    public_key = parts[2]

                    # Only allow user to register own key
                    if key_username != username:

                        send_message(client, "ERROR|Invalid public key username")

                        continue

                # -------------------------------------------------
                # Also support:
                # PUBLIC_KEY|public_key
                # -------------------------------------------------

                elif len(parts) == 2:

                    public_key = parts[1]

                else:

                    send_message(client, "ERROR|Invalid public key format")

                    continue

                # -------------------------------------------------
                # SAVE KEY
                # -------------------------------------------------

                database.save_public_key(username, public_key)

                with keys_lock:

                    public_keys[username] = public_key

                send_message(client, "KEY_SUCCESS|Public key registered")

                print(f"[KEY REGISTERED] " f"{username}")

            # =================================================
            # GET PUBLIC KEY
            # =================================================

            elif command.startswith("/key "):

                target = command.split(" ", 1)[1].strip()

                public_key = database.get_public_key(target)

                if public_key:

                    send_message(client, f"PUBLIC_KEY|" f"{target}|" f"{public_key}")

                else:

                    send_message(
                        client, "ERROR|Public key not available " f"for {target}"
                    )

            # =================================================
            # ENCRYPTED PRIVATE MESSAGE
            # =================================================

            elif command.startswith("/encrypted|"):

                result = handle_private_message(username, command)

                send_message(client, result)

            # =================================================
            # MESSAGE ACK
            # =================================================

            elif command.startswith("/ack|"):

                try:

                    message_id = int(command.split("|", 1)[1])

                    database.update_message_status(message_id, "delivered")

                except Exception:
                    pass

            # =================================================
            # USERS
            # =================================================

            elif command == "/users":

                send_user_list()

            # =================================================
            # CREATE GROUP
            # =================================================

            elif command.startswith("/create "):

                group_name = command.split(" ", 1)[1].strip()

                if not group_name:

                    send_message(client, "ERROR|Group name cannot be empty")

                    continue

                if database.create_group(group_name, username):

                    send_message(client, "GROUP_CREATED|" + group_name)

                    print(f"[GROUP CREATED] " f"{username} -> " f"{group_name}")

                else:

                    send_message(client, "ERROR|Group already exists")

            # =================================================
            # JOIN GROUP
            # =================================================

            elif command.startswith("/join "):

                group_name = command.split(" ", 1)[1].strip()

                if not group_name:

                    send_message(client, "ERROR|Group name cannot be empty")

                    continue

                if not database.get_group(group_name):

                    send_message(client, "ERROR|Group does not exist")

                elif database.add_member(group_name, username):

                    send_message(client, "JOINED|" + group_name)

                    print(f"[GROUP JOIN] " f"{username} -> " f"{group_name}")

                else:

                    send_message(client, "ERROR|Already a member")

            # =================================================
            # SHOW GROUPS
            # =================================================

            elif command == "/groups":

                send_group_list(client)

            # =================================================
            # GROUP MESSAGE
            # =================================================

            elif command.startswith("/groupmsg "):

                text = command.split(" ", 1)[1]

                parts = text.split(" ", 1)

                if len(parts) != 2:

                    send_message(client, "ERROR|Usage: " "/groupmsg groupname message")

                else:

                    group_name = parts[0]
                    message = parts[1]

                    result = handle_group_message(
                        username, f"/groupmsg|" f"{group_name}|" f"{message}"
                    )

                    send_message(client, result)

            # =================================================
            # PRIVATE MESSAGE HISTORY
            # =================================================

            elif command.startswith("/history "):

                target = command.split(" ", 1)[1].strip()

                history = database.get_messages(username, target)

                if not history:

                    send_message(client, "HISTORY|")

                else:

                    items = []

                    for sender, receiver, message, timestamp, status in history:

                        items.append(
                            f"{timestamp} | "
                            f"{sender} -> "
                            f"{receiver} | "
                            f"{message}"
                        )

                    send_message(client, "HISTORY|" + ";;".join(items))

            # =================================================
            # GROUP HISTORY
            # =================================================

            elif command.startswith("/grouphistory "):

                group_name = command.split(" ", 1)[1].strip()

                # Check group
                if not database.get_group(group_name):

                    send_message(client, "ERROR|Group does not exist")

                    continue

                history = database.get_group_messages(group_name)

                items = []

                for sender, message, timestamp in history:

                    items.append(f"{timestamp} | " f"{sender}: " f"{message}")

                send_message(client, "GROUPHISTORY|" + ";;".join(items))

            # =================================================
            # EXIT
            # =================================================

            elif command == "/exit":

                print(f"[EXIT] {username}")

                break

            # =================================================
            # UNKNOWN COMMAND
            # =================================================

            else:

                send_message(client, "ERROR|Unknown command")

    except ConnectionResetError:

        print(f"[CONNECTION RESET] {username}")

    except ConnectionAbortedError:

        print(f"[CONNECTION ABORTED] {username}")

    except Exception as e:

        print(f"[ERROR] {username}: {e}")

    finally:

        # =================================================
        # REMOVE CLIENT
        # =================================================

        if username:

            with clients_lock:

                clients.pop(username, None)

            with keys_lock:

                public_keys.pop(username, None)

            print(f"[DISCONNECTED] {username}")

            # -------------------------------------------------
            # Notify remaining users
            # -------------------------------------------------

            broadcast(f"SERVER|{username} left the chat")

            send_user_list()

        # =================================================
        # CLOSE SOCKET
        # =================================================

        try:

            client.close()

        except Exception:

            pass


# =========================================================
# START SERVER
# =========================================================


def start_server():

    global server
    global running

    running = True

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))

    server.listen(10)

    # -----------------------------------------------------
    # Allows CTRL+C to stop accept loop
    # -----------------------------------------------------

    server.settimeout(1)

    print("===================================")

    print("       SECURE CHAT SERVER")

    print("===================================")

    print(f"Server running on {HOST}:{PORT}")

    print("Authentication: ENABLED")

    print("Encryption: ENABLED 🔐")

    print("Groups: ENABLED 👥")

    print("Message History: ENABLED")

    print("Offline Messages: ENABLED")

    print("-----------------------------------")

    print("Waiting for clients...")

    print("Press CTRL+C to stop.")

    print("-----------------------------------")

    try:

        while running:

            try:

                client, address = server.accept()

                print(f"[NEW CONNECTION] " f"{address}")

                thread = threading.Thread(
                    target=handle_client, args=(client, address), daemon=True
                )

                thread.start()

            except socket.timeout:

                continue

    except KeyboardInterrupt:

        print("\nStopping server...")

    finally:

        running = False

        # =================================================
        # CLOSE ALL CLIENTS
        # =================================================

        with clients_lock:

            current_clients = list(clients.values())

            clients.clear()

        for client in current_clients:

            try:

                send_message(client, "SERVER_SHUTDOWN")

                client.close()

            except Exception:

                pass

        # =================================================
        # CLOSE SERVER SOCKET
        # =================================================

        try:

            server.close()

        except Exception:

            pass

        print("Server stopped.")


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    start_server()

import socket
import threading
import base64

import key_manager
import encryption

# =========================================
# CONFIGURATION
# =========================================

HOST = "127.0.0.1"
PORT = 5000

client = None
username = ""

key_cache = {}
key_events = {}

receiver_running = True

# Buffer for TCP line-based communication
receive_buffer = ""


# =========================================
# SEND
# =========================================


def send_line(message):
    global client

    try:
        client.sendall((message + "\n").encode())
        return True

    except Exception as e:
        print("\n❌ Send error:", e)
        return False


# =========================================
# RECEIVE ONE COMPLETE LINE
# =========================================


def receive_line():
    global client
    global receive_buffer

    try:

        while "\n" not in receive_buffer:

            data = client.recv(8192)

            if not data:
                return None

            receive_buffer += data.decode()

        line, receive_buffer = receive_buffer.split("\n", 1)

        return line.strip()

    except ConnectionResetError:
        return None

    except ConnectionAbortedError:
        return None

    except Exception:
        return None


# =========================================
# RECEIVE MESSAGES
# =========================================


def receive_messages():

    global receiver_running

    while receiver_running:

        try:

            message = receive_line()

            if message is None:

                print("\nServer disconnected.")
                break

            if not message:
                continue

            # =================================
            # READY OK
            # =================================

            if message == "READY_OK":

                continue

            # =================================
            # READY REQUEST
            # =================================

            elif message == "READY_REQUEST":

                continue

            # =================================
            # PUBLIC KEY
            # =================================

            elif message.startswith("PUBLIC_KEY|"):

                parts = message.split("|", 2)

                if len(parts) == 3:

                    target = parts[1]
                    public_key = parts[2]

                    key_cache[target] = public_key

                    if target in key_events:

                        key_events[target].set()

                    print(f"\n🔑 Public key received for {target}")

            # =================================
            # KEY SUCCESS
            # =================================

            elif message.startswith("KEY_SUCCESS|"):

                print("\n🔐 Public key registered.")

            # =================================
            # ENCRYPTED MESSAGE
            # =================================

            elif message.startswith("MESSAGE|"):

                parts = message.split("|", 3)

                if len(parts) == 4:

                    sender = parts[1]
                    message_id = parts[2]
                    encrypted_data = parts[3]

                    try:

                        # ---------------------------------
                        # SPLIT RSA + FERNET DATA
                        # ---------------------------------

                        encrypted_key, encrypted_message = encrypted_data.split("||", 1)

                        # ---------------------------------
                        # LOAD PRIVATE RSA KEY
                        # ---------------------------------

                        private_key = key_manager.load_private_key(username)

                        from cryptography.hazmat.primitives.asymmetric import (
                            padding,
                        )

                        from cryptography.hazmat.primitives import (
                            hashes,
                        )

                        # ---------------------------------
                        # DECODE RSA ENCRYPTED KEY
                        # ---------------------------------

                        encrypted_key_bytes = base64.b64decode(encrypted_key)

                        # ---------------------------------
                        # RSA DECRYPT
                        # ---------------------------------

                        symmetric_key = private_key.decrypt(
                            encrypted_key_bytes,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None,
                            ),
                        )

                        # ---------------------------------
                        # FERNET DECRYPT
                        # ---------------------------------

                        text = encryption.decrypt_message(
                            encrypted_message,
                            symmetric_key,
                        )

                        print(f"\n💬 {sender}: {text}")

                        # ---------------------------------
                        # ACKNOWLEDGE
                        # ---------------------------------

                        if message_id != "0":

                            send_line(f"/ack|{message_id}")

                    except Exception as e:

                        print("\n❌ Could not decrypt message.")

                        print(
                            "Error:",
                            e,
                        )

            # =================================
            # GROUP MESSAGE
            # =================================

            elif message.startswith("GROUP|"):

                parts = message.split("|", 3)

                if len(parts) >= 4:

                    group = parts[1]
                    sender = parts[2]
                    text = parts[3]

                    print(f"\n👥 [{group}] {sender}: {text}")

                elif len(parts) == 3:

                    group = parts[1]
                    text = parts[2]

                    print(f"\n👥 [{group}] {text}")

            # =================================
            # USERS
            # =================================

            elif message.startswith("USERS|"):

                users = message.split("|", 1)[1]

                print("\nOnline users:")

                if users:

                    for user in users.split("|"):

                        if user:

                            print(
                                "  -",
                                user,
                            )

                else:

                    print("  No users online")

            # =================================
            # GROUPS
            # =================================

            elif message.startswith("GROUPS|"):

                groups = message.split("|", 1)[1]

                print("\nGroups:")

                if groups:

                    for group in groups.split("|"):

                        if group:

                            print(
                                "  -",
                                group,
                            )

                else:

                    print("  No groups")

            # =================================
            # HISTORY
            # =================================

            elif message.startswith("HISTORY|"):

                history = message.split("|", 1)[1]

                print("\n========== MESSAGE HISTORY ==========")

                if history:

                    print(history)

                else:

                    print("No message history.")

                print("=====================================")

            # =================================
            # HISTORY END
            # =================================

            elif message == "HISTORY_END":

                print("=====================================")

            # =================================
            # GROUP HISTORY
            # =================================

            elif message.startswith("GROUPHISTORY|"):

                parts = message.split("|", 3)

                print("\n========== GROUP HISTORY ==========")

                if len(parts) >= 4:

                    sender = parts[1]
                    text = parts[2]

                    print(f"{sender}: {text}")

                elif len(parts) >= 2:

                    print(parts[1])

                print("===================================")

            # =================================
            # GROUP HISTORY END
            # =================================

            elif message == "GROUPHISTORY_END":

                print("===================================")

            # =================================
            # SENT
            # =================================

            elif message == "SENT":

                print("\n✓ Encrypted message sent")

            # =================================
            # ERROR
            # =================================

            elif message.startswith("ERROR|"):

                print("\n❌ " + message.split("|", 1)[1])

            # =================================
            # SERVER MESSAGE
            # =================================

            elif message.startswith("SERVER|"):

                print("\n" + message.split("|", 1)[1])

            # =================================
            # SERVER SHUTDOWN
            # =================================

            elif message == "SERVER_SHUTDOWN":

                print("\nServer is shutting down.")

                break

            # =================================
            # GROUP CREATED
            # =================================

            elif message.startswith("GROUP_CREATED|"):

                print("\n✓ Group created: " + message.split("|", 1)[1])

            # =================================
            # JOINED
            # =================================

            elif message.startswith("JOINED|"):

                print("\n✓ Joined group: " + message.split("|", 1)[1])

            print(
                "> ",
                end="",
                flush=True,
            )

        except ConnectionResetError:

            print("\nServer connection lost.")

            break

        except ConnectionAbortedError:

            print("\nServer connection aborted.")

            break

        except Exception as e:

            print(
                "\n❌ Receiver error:",
                e,
            )

            break


# =========================================
# GET RECIPIENT PUBLIC KEY
# =========================================


def get_recipient_key(target):

    # ---------------------------------
    # CHECK CACHE
    # ---------------------------------

    if target in key_cache:

        return key_cache[target]

    # ---------------------------------
    # CREATE EVENT
    # ---------------------------------

    event = threading.Event()

    key_events[target] = event

    try:

        send_line(f"/key {target}")

    except Exception as e:

        print(
            "\n❌ Could not request public key:",
            e,
        )

        key_events.pop(
            target,
            None,
        )

        return None

    # ---------------------------------
    # WAIT
    # ---------------------------------

    event.wait(5)

    key_events.pop(
        target,
        None,
    )

    return key_cache.get(target)


# =========================================
# SEND ENCRYPTED MESSAGE
# =========================================


def send_encrypted_message(target, text):

    # ---------------------------------
    # GET RECIPIENT PUBLIC KEY
    # ---------------------------------

    public_key_text = get_recipient_key(target)

    if not public_key_text:

        print(f"\n❌ Public key for {target} not available.")

        return

    try:

        # ---------------------------------
        # LOAD PUBLIC KEY
        # ---------------------------------

        public_key = key_manager.public_key_from_text(public_key_text)

        # ---------------------------------
        # GENERATE FERNET KEY
        # ---------------------------------

        symmetric_key = encryption.generate_key()

        # ---------------------------------
        # ENCRYPT MESSAGE WITH FERNET
        # ---------------------------------

        encrypted_message = encryption.encrypt_message(
            text,
            symmetric_key,
        )

        # ---------------------------------
        # RSA IMPORTS
        # ---------------------------------

        from cryptography.hazmat.primitives.asymmetric import (
            padding,
        )

        from cryptography.hazmat.primitives import (
            hashes,
        )

        # ---------------------------------
        # ENCRYPT FERNET KEY WITH RSA
        # ---------------------------------

        encrypted_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # ---------------------------------
        # BASE64 RSA KEY
        # ---------------------------------

        encrypted_key_text = base64.b64encode(encrypted_key).decode()

        # ---------------------------------
        # COMBINE
        # ---------------------------------

        encrypted_data = encrypted_key_text + "||" + encrypted_message

        # ---------------------------------
        # SEND
        # ---------------------------------

        command = "/encrypted|" + target + "|" + encrypted_data

        send_line(command)

    except Exception as e:

        print(
            "\n❌ Encryption error:",
            e,
        )


# =========================================
# AUTHENTICATION
# =========================================


def authenticate():

    global client

    print("\n===================================")

    print("          SECURE CHAT LOGIN")

    print("===================================")

    print("1. Login")

    print("2. Register")

    print("3. Exit")

    choice = input("Choose: ").strip()

    # ---------------------------------
    # EXIT
    # ---------------------------------

    if choice == "3":

        return None

    # ---------------------------------
    # INVALID
    # ---------------------------------

    if choice not in ["1", "2"]:

        print("\nInvalid choice.")

        return None

    # ---------------------------------
    # SERVER AUTH REQUEST
    # ---------------------------------

    response = receive_line()

    if response != "AUTH_REQUEST":

        print("\n❌ Unexpected server response.")

        print(
            "Server response:",
            response,
        )

        return None

    # ---------------------------------
    # LOGIN / REGISTER
    # ---------------------------------

    if choice == "1":

        send_line("LOGIN")

    else:

        send_line("REGISTER")

    # ---------------------------------
    # USERNAME PROMPT
    # ---------------------------------

    response = receive_line()

    if response is None:

        print("\n❌ Server disconnected.")

        return None

    print(response)

    if response != "USERNAME":

        print("\n❌ Unexpected server response.")

        return None

    username_input = input("Username: ").strip()

    send_line(username_input)

    # ---------------------------------
    # PASSWORD PROMPT
    # ---------------------------------

    response = receive_line()

    if response is None:

        print("\n❌ Server disconnected.")

        return None

    print(response)

    if response != "PASSWORD":

        print("\n❌ Unexpected server response.")

        return None

    password = input("Password: ")

    send_line(password)

    # ---------------------------------
    # AUTH RESULT
    # ---------------------------------

    response = receive_line()

    if response is None:

        print("\n❌ Server disconnected.")

        return None

    print("\n" + response)

    # ---------------------------------
    # SUCCESS
    # ---------------------------------

    if response.startswith("AUTH_SUCCESS|"):

        return username_input

    # ---------------------------------
    # FAILURE
    # ---------------------------------

    print("\n❌ Login failed.")

    return None


# =========================================
# CHAT
# =========================================


def chat(user):

    global username
    global receiver_running

    username = user

    receiver_running = True

    print("\n===================================")

    print("        SECURE CHAT STARTED")

    print("===================================")

    print("\nEncryption: ENABLED 🔐")

    print("\nAvailable commands:")

    print("/msg username message")

    print("/key username")

    print("/users")

    print("/create groupname")

    print("/join groupname")

    print("/groups")

    print("/groupmsg groupname message")

    print("/history username")

    print("/grouphistory groupname")

    print("/exit")

    # ---------------------------------
    # RECEIVER THREAD
    # ---------------------------------

    receiver_thread = threading.Thread(
        target=receive_messages,
        daemon=True,
    )

    receiver_thread.start()

    # ---------------------------------
    # CHAT LOOP
    # ---------------------------------

    while True:

        try:

            command = input("> ")

            if not command:

                continue

            # =================================
            # PRIVATE MESSAGE
            # =================================

            if command.startswith("/msg "):

                parts = command.split(
                    " ",
                    2,
                )

                if len(parts) != 3:

                    print("Usage: /msg username message")

                    continue

                target = parts[1]
                text = parts[2]

                send_encrypted_message(
                    target,
                    text,
                )

            # =================================
            # EXIT
            # =================================

            elif command == "/exit":

                receiver_running = False

                try:

                    send_line("/exit")

                except Exception:

                    pass

                break

            # =================================
            # NORMAL COMMANDS
            # =================================

            else:

                try:

                    send_line(command)

                except Exception as e:

                    print(
                        "\n❌ Error:",
                        e,
                    )

                    break

        except KeyboardInterrupt:

            receiver_running = False

            try:

                send_line("/exit")

            except Exception:

                pass

            break

        except Exception as e:

            print(
                "\n❌ Error:",
                e,
            )

            break


# =========================================
# MAIN
# =========================================


def main():

    global client
    global receive_buffer

    try:

        # =================================
        # CREATE SOCKET
        # =================================

        client = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        # =================================
        # CONNECT
        # =================================

        client.connect((HOST, PORT))

        # Reset buffer
        receive_buffer = ""

        # =================================
        # AUTHENTICATION
        # =================================

        user = authenticate()

        if not user:

            client.close()

            return

        # =================================
        # GENERATE RSA KEYS
        # =================================

        try:

            key_manager.generate_keys(user)

            print("\n🔐 Encryption keys ready.")

        except Exception as e:

            print("\n❌ Could not generate encryption keys:")

            print(e)

            client.close()

            return

        # =================================
        # WAIT FOR READY REQUEST
        # =================================

        response = receive_line()

        if response is None:

            print("\n❌ Server disconnected during handshake.")

            client.close()

            return

        print(response)

        if response != "READY_REQUEST":

            print("\n❌ Unexpected server response.")

            print(
                "Server response:",
                response,
            )

            client.close()

            return

        # =================================
        # SEND READY
        # =================================

        send_line("READY")

        # =================================
        # WAIT FOR READY OK
        # =================================

        response = receive_line()

        if response is None:

            print("\n❌ Server disconnected during handshake.")

            client.close()

            return

        if response != "READY_OK":

            print("\n❌ Server handshake failed.")

            print(
                "Server response:",
                response,
            )

            client.close()

            return

        print("\n✅ Server handshake successful.")

        # =================================
        # SEND PUBLIC KEY
        # =================================

        public_key = key_manager.get_public_key_text(user)

        send_line("PUBLIC_KEY|" + user + "|" + public_key)

        print("🔑 Public key registered.")

        # =================================
        # START CHAT
        # =================================

        chat(user)

    except ConnectionRefusedError:

        print("\n❌ Could not connect to server.")

        print("Make sure server.py is running.")

    except ConnectionResetError:

        print("\n❌ Server forcibly closed the connection.")

    except ConnectionAbortedError:

        print("\n❌ Connection was aborted.")

    except Exception as e:

        print(
            "\n❌ Error:",
            e,
        )

    finally:

        try:

            if client:

                client.close()

        except Exception:

            pass


# =========================================
# START
# =========================================

if __name__ == "__main__":

    main()

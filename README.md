# 🔐 SecureChat — Secure Multi-Client Chat Application

A **secure, concurrent, multi-client chat application** built using **TCP socket programming, multithreading, SQLite, and RSA encryption**.

SecureChat allows multiple users to connect to a central server, communicate in real time, send private messages, create and join groups, and access message history.

---

## 📌 Features

### 👥 Multi-Client Communication

* Multiple clients can connect to the server simultaneously.
* Each client is handled using a dedicated thread.
* Real-time message broadcasting between connected users.

### 🔒 Secure Communication

* RSA-based encryption is implemented for secure message handling.
* Each user can have their own cryptographic keys.
* Encryption/decryption is integrated into the communication workflow.

### 💬 Private Messaging

Users can send messages directly to another user.

```text
/msg username message
```

Example:

```text
/msg Alice Hey, how are you?
```

### 👨‍👩‍👧‍👦 Group Chat

Users can create and participate in group conversations.

Create a group:

```text
/create groupname
```

Join a group:

```text
/join groupname
```

Send a group message:

```text
/groupmsg groupname message
```

View available groups:

```text
/groups
```

### 📜 Message History

Private conversation history:

```text
/history username
```

Group conversation history:

```text
/grouphistory groupname
```

### 👤 Online Users

View currently connected users:

```text
/users
```

### 🚪 Exit

Disconnect from the server:

```text
/exit
```

---

## 🏗️ System Architecture

```text
                 ┌─────────────────────┐
                 │      Client 1       │
                 │  Chat Interface     │
                 └──────────┬──────────┘
                            │
                            │ TCP
                            │
                 ┌──────────▼──────────┐
                 │                     │
                 │   SecureChat Server │
                 │                     │
                 │  ┌───────────────┐  │
                 │  │ Client Threads│  │
                 │  └───────────────┘  │
                 │                     │
                 │  Message Routing    │
                 │  Group Management   │
                 │  Authentication     │
                 │  Encryption         │
                 └───────┬───────┬─────┘
                         │       │
                    ┌────▼───┐ ┌─▼──────┐
                    │ Client │ │ Client │
                    │    2   │ │    3   │
                    └────────┘ └────────┘

                         │
                         ▼
                  ┌─────────────┐
                  │   SQLite DB │
                  │             │
                  │ Users       │
                  │ Messages    │
                  │ Groups      │
                  └─────────────┘
```

---

## 🛠️ Technologies Used

| Technology              | Purpose                               |
| ----------------------- | ------------------------------------- |
| **Python**              | Core application development          |
| **TCP Sockets**         | Client-server communication           |
| **Multithreading**      | Concurrent client handling            |
| **RSA**                 | Cryptographic operations              |
| **SQLite**              | User and message data storage         |
| **HTML/CSS/JavaScript** | Web-based interface, where applicable |

---

## 📂 Project Structure

A typical project structure is:

```text
SecureChat/
│
├── server/
│   ├── server.py
│   ├── database.py
│   ├── encryption.py
│   └── ...
│
├── client/
│   ├── client.py
│   └── ...
│
├── keys/
│   └── ...
│
├── templates/
│   └── chat.html
│
├── static/
│   ├── style.css
│   └── script.js
│
├── database/
│   └── ...
│
├── README.md
└── requirements.txt
```

> Adjust the structure above to match the actual files in your repository.

---

## 🔄 How It Works

### 1. User Registration

A new user registers with the application.

User information is stored in the SQLite database.

```text
Client
   ↓
Registration
   ↓
Server
   ↓
SQLite Database
```

### 2. User Login

The client sends authentication information to the server.

The server verifies the credentials against the database.

```text
Client → Server → SQLite → Authentication Result
```

### 3. Client Connection

After successful authentication, the client establishes a TCP connection with the server.

The server creates a dedicated thread for the client.

```text
                Server
                  │
       ┌──────────┼──────────┐
       │          │          │
   Thread 1   Thread 2   Thread 3
       │          │          │
    Client 1   Client 2   Client 3
```

### 4. Message Routing

When a client sends a message, the server determines the destination.

For a normal broadcast:

```text
Client → Server → All Connected Clients
```

For a private message:

```text
Client A → Server → Client B
```

For a group message:

```text
Client A
   ↓
 Server
   ↓
Group Members
```

---

## 🔐 Encryption

SecureChat incorporates **RSA cryptography** for secure communication.

The basic public-key cryptography workflow is:

```text
                RSA Key Generation
                       │
              ┌────────┴────────┐
              │                 │
         Public Key         Private Key
              │                 │
              ▼                 ▼
          Encryption         Decryption
```

The public key can be used for encryption, while the corresponding private key is used for decryption.

### Security Considerations

* Private keys should never be committed to GitHub.
* Credentials should not be hardcoded.
* Sensitive configuration should be stored in environment variables.
* Database files containing real user information should not be uploaded.

---

## 🧵 Concurrency Model

SecureChat uses **multithreading** to support multiple clients concurrently.

When a new client connects:

```python
client_socket, address = server_socket.accept()

thread = threading.Thread(
    target=handle_client,
    args=(client_socket, address)
)

thread.start()
```

This allows the server to handle multiple clients without blocking other connections.

---

## 💻 Supported Commands

| Command                       | Description               |
| ----------------------------- | ------------------------- |
| `/msg username message`       | Send a private message    |
| `/users`                      | Display online users      |
| `/create groupname`           | Create a new group        |
| `/join groupname`             | Join a group              |
| `/groups`                     | Display available groups  |
| `/groupmsg groupname message` | Send a group message      |
| `/history username`           | View private chat history |
| `/grouphistory groupname`     | View group chat history   |
| `/exit`                       | Disconnect from server    |

---

## 🚀 Getting Started

### Prerequisites

Make sure Python is installed:

```bash
python --version
```

Recommended:

```text
Python 3.x
```

---

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/SecureChat.git
```

Move into the project:

```bash
cd SecureChat
```

---

### 2. Create a Virtual Environment

Windows:

```bash
python -m venv venv
```

Activate it:

```bash
venv\Scripts\activate
```

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

---

### 3. Install Dependencies

If `requirements.txt` exists:

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Application

### Start the Server

From the project directory:

```bash
python server.py
```

The server should start listening for incoming TCP connections.

### Start a Client

Open another terminal:

```bash
python client.py
```

Run multiple client instances to test multi-client communication.

For example:

```text
Terminal 1 → Server
Terminal 2 → Client 1
Terminal 3 → Client 2
Terminal 4 → Client 3
```

---

## 🧪 Example Session

### Client 1

```text
Connected to SecureChat Server

Username: Alice

/users

Online Users:
Alice
Bob
Charlie
```

Private message:

```text
/msg Bob Hello Bob!
```

### Group Communication

```text
/create developers
```

Then:

```text
/join developers
```

Send a message:

```text
/groupmsg developers Hello everyone!
```

---

## 🗄️ Database

SecureChat uses **SQLite** for persistent data storage.

The database can store information such as:

```text
Users
├── Username
├── Password / Authentication Data
└── Account Information

Messages
├── Sender
├── Receiver
├── Message
└── Timestamp

Groups
├── Group Name
└── Members
```

The exact schema depends on the current implementation.

---

## 🛡️ Security Features

SecureChat was designed with the following security concepts:

* 🔐 RSA public-key cryptography
* 🔑 Key generation
* 👤 User authentication
* 🧵 Concurrent client handling
* 🔒 Private messaging
* 👥 Controlled group communication
* 💾 Persistent message storage
* 🚫 Separation of sensitive configuration from source code

---

## 🎯 Project Objectives

The primary objectives of SecureChat are:

1. Implement TCP-based client-server communication.
2. Support multiple concurrent clients.
3. Implement real-time message routing.
4. Provide private and group communication.
5. Implement user authentication.
6. Store relevant information using SQLite.
7. Apply cryptographic techniques to improve communication security.
8. Provide message history functionality.
9. Demonstrate practical use of networking and concurrency concepts.

---

## 📚 Concepts Demonstrated

This project demonstrates practical implementation of:

* TCP/IP Networking
* Client-Server Architecture
* Socket Programming
* Multithreading
* Synchronization
* Message Routing
* Private Communication
* Group Communication
* Authentication
* Cryptography
* Database Management
* Concurrent Programming

---

## 🔮 Future Enhancements

Potential improvements include:

* End-to-end encryption using modern authenticated encryption.
* Secure key exchange.
* Password hashing using Argon2 or bcrypt.
* HTTPS/TLS-secured communication.
* File and image sharing.
* Message delivery/read status.
* Typing indicators.
* Online/offline presence.
* Message deletion and editing.
* Improved graphical user interface.
* Voice/video calling.
* Push notifications.
* Docker-based deployment.

---

## ⚠️ Disclaimer

This project is developed for **educational and academic purposes** to demonstrate networking, concurrency, database management, and cryptography concepts.

It should not be considered production-grade secure messaging software without further security auditing, threat modeling, and hardening.

---

## 👨‍💻 Team

**SecureChat — Secure Multi-Client Chat Application**

Developed as an academic project.

### Team Members

* **24BCE0370**
* **24BCE0898**
* **24BCT0231**

---

## ⭐ Project Highlights

```text
                SECURECHAT
                    │
       ┌────────────┼────────────┐
       │            │            │
     TCP         Threads       RSA
       │            │            │
       └────────────┼────────────┘
                    │
             ┌──────▼──────┐
             │   Chat      │
             │ Application │
             └──────┬──────┘
                    │
              ┌─────▼─────┐
              │  SQLite   │
              └───────────┘
```

**Secure communication • Concurrent clients • Private messaging • Group chat • Message history**

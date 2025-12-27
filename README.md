# Enhanced UDP File Transfer System (TFTP-Based)

A robust, secure, and reliable file transfer system implemented in C over UDP. This project mimics the standard TFTP (Trivial File Transfer Protocol) while introducing critical enhancements for modern networking needs, such as encryption, file recovery, and improved packet management.

## 🎯 Project Overview

This system provides a complete client-server architecture for network file operations, including uploading, downloading, and deleting files. Since UDP is natively unreliable, the system implements a manual Acknowledgment (ACK) mechanism to ensure data integrity.

## 🚀 Key Improvements Over Standard TFTP

1.  **Enhanced Reliability**: Implements a Stop-and-Wait ARQ mechanism to handle packet loss and retransmissions.
2.  **Security**: Full file encryption using **AES-128-CFB** to ensure secure communication between client and server.
3.  **Data Integrity**: Verification of file integrity using **MD5** checksums after transfer.
4.  **Backup & Recovery**: The server automatically creates a backup of every uploaded file in a dedicated `backup/` directory.
5.  **Improved Management**: Increased packet payload size (1024 bytes) for better efficiency.

## 🛠 Technical Specifications

*   **Protocol**: UDP (User Datagram Protocol).
*   **Port**: Default listening on port `6969`.
*   **Encryption**: OpenSSL AES.
*   **Operations Supported**:
    *   **RRQ (Read Request)**: Download a file from the server.
    *   **WRQ (Write Request)**: Upload a file to the server.
    *   **Delete Request**: Remove a file from the server.

## 📁 Project Structure

*   `server.c`: Server-side logic including request listening, file management, encryption/decryption, and packet acknowledgment.
*   `client.c`: Client-side logic for initiating requests, managing reliable uploads/downloads, and user interface.
*   `udp_file_transfer.h`: Protocol definitions, custom packet structures, shared constants, and configuration.

## ⚙️ How to Build and Run

### Prerequisites
You need **OpenSSL** installed on your system for encryption and hashing.
*   **Linux (Ubuntu/Debian)**: `sudo apt-get install libssl-dev`
*   **Windows**: Ensure OpenSSL libraries are linked correctly in your environment.

### 1. Compile the Project
You must link against the OpenSSL libraries (`-lssl -lcrypto`).

```bash
# Compile Server
gcc server.c -o server -lssl -lcrypto

# Compile Client
gcc client.c -o client -lssl -lcrypto
```

### 2. Start the Server
Run the server executable. It will create a `backup/` directory if it doesn't exist and start listening on port 6969.

```bash
./server
```

### 3. Run the Client
Run the client executable. It provides an interactive menu for operations.

```bash
./client
```

**Client Menu:**
```text
Choose operation: 1-Read, 2-Write, 3-Delete, 0-Exit:
```
*   **1-Read**: Download a file from the server.
*   **2-Write**: Upload a local file to the server.
*   **3-Delete**: Delete a file from the server.

## 🔒 Security & Backup
*   **Encryption**: All file data sent over the network is encrypted. The server decrypts uploads and encrypts downloads.
*   **Backups**: When a file is successfully uploaded to the server, a copy is immediately saved in the `backup/` folder on the server side.

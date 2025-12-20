Enhanced UDP File Transfer System (TFTP-Based)
A robust, secure, and reliable file transfer system implemented in C over UDP. This project mimics the standard TFTP (Trivial File Transfer Protocol) while introducing critical enhancements for modern networking needs, such as encryption, file recovery, and improved packet management.



🎯 Project Overview
This system provides a complete client-server architecture for network file operations, including uploading, downloading, and deleting files. Since UDP is natively unreliable, the system implements a manual Acknowledgment (ACK) mechanism to ensure 100% data integrity.





🚀 Key Improvements Over Standard TFTP

Enhanced Reliability: Implements a Stop-and-Wait ARQ mechanism to handle packet loss.





Security: Full file encryption using AES to ensure secure communication between client and server.




Data Integrity: Verification of file integrity using checksums/hashes (e.g., MD5).



Backup & Recovery: The server automatically backs up uploaded files, allowing for recovery in case of system failure.




Improved Management: Larger packet sizes and more efficient resending mechanisms compared to standard TFTP.


🛠 Technical Specifications

Protocol: UDP (User Datagram Protocol).


Port: Default listening on port 6969.


Packet Size: Configurable chunks (Standard: 512 bytes).



Operations Supported: * RRQ (Read Request): Download a file.



WRQ (Write Request): Upload a file.



Delete Request: Remove a file from the server.


📁 Project Structure

server.c: Server-side logic including request listening, file management, and packet acknowledgment.



client.c: Client-side logic for initiating requests and managing reliable uploads/downloads.



udp_file_transfer.h: Protocol definitions, custom packet structures, and shared constants.


⚙️ How to Run
1. Compile the Project
Using gcc (or your provided Makefile):

Bash

gcc server.c -o server
gcc client.c -o client
2. Start the Server
The server will start listening for incoming UDP requests:

Bash

./server
3. Use the Client
To Download a file (RRQ):

Bash

./client download <filename>
To Upload a file (WRQ):

Bash

./client upload <filename>
To Delete a file:

Bash

./client delete <filename>
🛡 Security & Reliability logic

Handshake: Every request (RRQ/WRQ) must be acknowledged before data starts flowing.


ACK Cycle: For every packet sent, the sender waits for an ACK. If a timeout occurs, the packet is resent.




AES Encryption: All data blocks are encrypted before being put "on the wire".

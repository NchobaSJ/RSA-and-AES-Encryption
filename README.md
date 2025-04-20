# Secure Client-Server Communication with RSA and AES Encryption

This project demonstrates a secure client-server communication system using a combination of RSA and AES encryption algorithms to ensure confidentiality, integrity, and authentication.

## Features

- **Secure Key Exchange**: Uses RSA public-key cryptography to securely exchange AES keys
- **Symmetric Encryption**: AES-256 in CBC mode for efficient encrypted communication
- **Message Integrity**: Digital signatures (SHA256withRSA) to verify message authenticity
- **Initialization Vectors**: Random IVs for AES CBC mode to ensure unique ciphertexts
- **Mutual Authentication**: Both client and server verify each other's identity through digital signatures

## Technical Details

### Encryption Protocols
- **RSA 2048-bit**: Used for:
  - Secure AES key exchange
  - Digital signatures for message authentication
- **AES-256 CBC**: Used for:
  - Encrypting all subsequent communications
  - Requires Initialization Vector (IV) for each session

### Security Measures
- All AES keys are signed by their originator (client or server)
- Each message is signed before encryption
- IV is generated randomly for each session
- Key verification before establishing secure channel

## How It Works

1. **Initial Handshake**:
   - Server and client generate RSA key pairs
   - They exchange public keys
   - Client generates AES key and IV
   - Client encrypts AES key with server's public key
   - Client signs the AES key with its private key

2. **Secure Communication**:
   - All messages are:
     1. Signed by sender
     2. Combined with signature
     3. Encrypted with AES
     4. Sent to recipient
   - Recipient:
     1. Decrypts with AES
     2. Separates message and signature
     3. Verifies signature

## Prerequisites

- Java 8 or later
- No additional libraries required (uses standard Java Cryptography Architecture)

## How to Run

1. **Start the Server**:
   ```bash
   javac Server.java
   java Server
2. **Start the Client (in a separate terminal):**
   ```bash
   javac Client.java
   java Client
3. **Communication:**
   -After connection is established, both client and server can type messages
   -Messages will be encrypted, signed, and verified automatically
   -Type your message and press Enter to send

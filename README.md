
# CS3750 Project 01 - Cryptographic Application

## Project Overview

This project implements a simplified cryptographic application using RSA and AES encryption. It consists of three programs: a **Key Generation** program, a **Sender** program, and a **Receiver** program. The goal is to securely transmit a message between a sender and receiver using public-key cryptography and message authentication.

### Components

- **KeyGen Program**: 
  - Generates a pair of RSA public and private keys for both the sender (X) and the receiver (Y).
  - Saves the keys to respective files (`XPublic.key`, `XPrivate.key`, `YPublic.key`, and `YPrivate.key`).
  - Generates a 16-character AES symmetric key (`symmetric.key`) used for encrypting the message.

- **Sender Program**:
  - Prompts the user to provide the name of the message file.
  - Calculates the SHA-256 digest of the message and prompts the user whether they want to invert the first byte of the digest.
  - AES-encrypts the digest and appends the message to the encrypted digest.
  - RSA-encrypts the combined AES-encrypted digest and message using the receiver's public key (`YPublic.key`) and saves the result in `message.rsacipher`.

- **Receiver Program**:
  - Decrypts the RSA-encrypted message using the receiver's private key (`YPrivate.key`).
  - Extracts and decrypts the AES-encrypted digest.
  - Recalculates the SHA-256 digest of the received message and compares it with the decrypted digest to verify message integrity.
  - Outputs whether the message integrity check passes or fails.

## Project Structure

```
Prj01/
│
├── KeyGen/
│   ├── KeyGen.java       # Key generation program
│   ├── XPublic.key       # Public key for sender (X)
│   ├── XPrivate.key      # Private key for sender (X)
│   ├── YPublic.key       # Public key for receiver (Y)
│   ├── YPrivate.key      # Private key for receiver (Y)
│   └── symmetric.key     # AES symmetric key for encryption
│
├── Sender/
│   ├── sender.java       # Sender program
│   ├── message.rsacipher # RSA-encrypted message
│   └── message.add-msg   # AES-encrypted digest and original message
│
└── Receiver/
    ├── receiver.java     # Receiver program
    └── message.add-msg   # Decrypted AES message + digest
```

## Usage Instructions

### 1. Key Generation
To generate RSA keys and the AES key:
```bash
javac KeyGen/KeyGen.java
java KeyGen/KeyGen
```

This will create the key files (`XPublic.key`, `XPrivate.key`, `YPublic.key`, `YPrivate.key`) and the AES key file (`symmetric.key`).

### 2. Sender Program
To encrypt a message:
```bash
javac Sender/sender.java
java Sender/sender
```
- The program will prompt you for the name of the message file (e.g., `message.txt`).
- It will then create an encrypted file `message.rsacipher`.

### 3. Receiver Program
To decrypt the message:
```bash
javac Receiver/receiver.java
java Receiver/receiver
```
- The program will prompt you for the name of the output file where the decrypted message will be stored (e.g., `decryptedMessage.txt`).
- It will display whether the integrity check passed or failed.

### 4. Testing
The programs have been tested for various cases:
- With and without message authentication errors (using the "invert first byte" option).
- With small to large message files, both in text and binary formats.

### Redirect Output for Testing
To capture the program output:
```bash
java prog_name_args | tee output_file.txt
```
For example:
```bash
java Sender/sender | tee tst_Sender.txt
java Receiver/receiver | tee tst_Receiver.txt
```

## Example Test Cases

1. **Normal Flow**: No byte inversion in the digest.
2. **Inverted Digest Byte**: The first byte of the digest is inverted, causing the integrity check to fail.

## Dependencies

- **Java 8+** for compilation and execution of the programs.
- No external libraries are required; the programs use standard Java security libraries.

## License

This project is open-source and available under the [MIT License](LICENSE).

# Lesson 02

## Table of Contents

- [Disclaimer](#disclaimer)
- [Summary](#summary)
  - [HTTPS Workflow](#https-workflow)
    - [1. TLS Handshake](#1-tls-handshake)
    - [2. Symmetric Encryption](#2-symmetric-encryption)
    - [3. Secure Data Transmission](#3-secure-data-transmission)
    - [4. Session Closure](#4-session-closure)
  - [SSL/TLS Validation](#ssltls-validation)
- [Conclusion](#conclusion)

## Disclaimer

This document serves as a quick summary of the lesson and may not encompass the entirety of the content discussed. It is intended to provide a brief overview and should be considered merely as a reference to contextualize the exercises. For a comprehensive understanding of all topics, concepts, and discussions, referring to the full lesson material is recommended.

## Summary

In the second lesson, we continued from the conclusion of Lesson 1, delving deeper into the implementation of Secure 
Web (HTTPS) protocols. The focus was on understanding the hybrid encryption model that underpins HTTPS, combining the 
strengths of both Public Key Infrastructure (PKI)/Asymmetric encryption and Symmetric encryption. Initially, the session 
emphasized how PKI and Asymmetric encryption are utilized for the secure exchange of a session key. This key exchange 
process is critical for establishing a secure channel between the client and the server. Following the successful 
exchange of the session key, the lesson explored the use of Symmetric encryption for the efficient and secure 
transmission of data over this established channel. This dual approach leverages the security and authentication 
benefits of Asymmetric encryption for key exchange, while capitalizing on the speed and efficiency of Symmetric 
encryption for data transfer, illustrating the comprehensive security measures essential for safeguarding 
internet-facing systems and ensuring the confidentiality and integrity of user data.

### HTTPS Workflow:

The HTTPS (Hypertext Transfer Protocol Secure) protocol is essential for ensuring secure communication over the internet, particularly in sensitive transactions involving personal, financial, or other private data. It uses a combination of cryptographic protocols to protect data in transit between a client (e.g., a web browser) and a server. Here's a detailed breakdown of how HTTPS works to safeguard data:

#### 1. **TLS Handshake**
The initial phase of an HTTPS connection is the TLS (Transport Layer Security) handshake, which securely establishes the session's encryption parameters without transmitting the encryption keys over the network. The steps are:

- **ClientHello**: The client initiates the handshake by sending a ClientHello message, which includes the TLS version it supports, a list of supported cipher suites (encryption algorithms), and a randomly generated client nonce (number used once).

- **ServerHello**: The server responds with a ServerHello message, selecting the TLS version and cipher suite from the options provided by the client, and sends its own random nonce.

- **Certificate Exchange**: The server sends its SSL certificate, which includes the server's public key, to the client. The certificate is typically issued by a trusted Certificate Authority (CA).

- **Key Exchange**: The client verifies the server's certificate (as detailed in your previous question) and uses the server's public key to encrypt a pre-master secret. This encrypted pre-master secret is then sent to the server.

- **Session Keys Generation**: Both the client and the server use the pre-master secret and the nonces to generate the same session keys for symmetric encryption.

#### 2. **Symmetric Encryption**
Once the TLS handshake is complete, and the session keys are established, all subsequent data transmitted between the client and server is encrypted with symmetric encryption using the agreed-upon cipher suite. This includes:

- **Data Encryption**: The client and server use the session keys to encrypt and decrypt the data exchanged. Symmetric encryption ensures that data is encrypted quickly and efficiently, suitable for high-volume data transfer.

- **Data Integrity**: Alongside encryption, mechanisms like MAC (Message Authentication Code) or AEAD (Authenticated Encryption with Associated Data) ensure the integrity and authenticity of the data. These mechanisms protect against tampering and forgery.

#### 3. **Secure Data Transmission**
With HTTPS, all data sent between the client and server is encrypted, ensuring that:

- **Eavesdropping Protection**: Intermediaries or attackers who intercept the data cannot decipher it without the encryption keys.

- **Man-in-the-Middle (MitM) Attack Prevention**: The initial certificate exchange and verification process ensures that the client communicates with the legitimate server, not an impersonator.

- **Data Integrity**: Alterations to the data during transit are detectable and prevent unauthorized modifications.

#### 4. **Session Closure**
- When the session ends, either the client or server can securely terminate the connection. The session keys are discarded, ensuring that each session is uniquely encrypted and that keys cannot be reused for future sessions.

### SSL/TLS Validation:

During a TLS (Transport Layer Security) handshake, the browser performs several checks on a server's certificate to establish a secure connection. These checks are crucial for ensuring the authenticity, integrity, and confidentiality of the data exchanged between the browser and the server. Here are the primary controls performed:

1. **Certificate Validity Period Check**: The browser verifies that the server's certificate is within its validity period, i.e., the current date and time are between the "Not Before" and "Not After" timestamps of the certificate.
2. **Certificate Authority (CA) Trust Check**: The browser checks whether the server's certificate was issued by a Certificate Authority (CA) that the browser trusts. This is done by comparing the issuing CA's certificate against a list of trusted CA certificates pre-installed in the browser or the operating system.
3. **Certificate Revocation Check**: The browser checks if the certificate has been revoked by its issuer before the expiration of its validity period. This can be done through various mechanisms such as CRL (Certificate Revocation List) or OCSP (Online Certificate Status Protocol).
4. **Domain Name Match**: The browser verifies that the domain name in the URL matches the domain name specified in the certificate's "Common Name" or "Subject Alternative Name" fields. This ensures that the certificate is actually issued for the server the browser is trying to communicate with.
5. **Certificate Chain Validation**: The browser validates the entire certificate chain, from the server's certificate up to the root CA certificate. This involves verifying that each certificate in the chain is signed by the certificate that directly follows it in the chain, up to a trusted root CA certificate.
6. **Public Key Cryptography Checks**: The browser uses the public key in the server's certificate to encrypt a piece of information that can only be decrypted by the corresponding private key possessed by the server. This process verifies that the server has the private key corresponding to the public key in the certificate, proving ownership of the certificate.
7. **Signature Verification**: The browser verifies the digital signature on the certificate using the public key of the issuer (CA). This ensures that the certificate has not been tampered with and was indeed issued by the claimed CA.
8. **Object Identifiers Validation**: The browser should check the OID of the server to ensure the server was created for Server Authentication [OID 1.3.6.1.5.5.7.3.1 id-kp-serverAuth](https://oidref.com/1.3.6.1.5.5.7.3.1)

### Conclusion

The lesson concluded with an in-depth discussion on how HTTPS effectively combines the best features of asymmetric 
and symmetric encryption, leveraging the former for secure key exchange and the latter for efficient data encryption. 
This multi-layered approach ensures the confidentiality, integrity, and authenticity of data transmitted over the 
internet, forming the backbone of secure online communication.


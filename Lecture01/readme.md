# Lesson 01

## Table of Contents

- [Disclaimer](#disclaimer)
- [Summary](#summary)
  - [Prerequisites for a Secure Web System](#prerequisites-for-a-secure-web-system)
  - [Major Approaches Developed](#major-approaches-developed)
  - [Conclusion](#conclusion)
- [Exercise](#exercise)
  - [Solutions](#solutions)

## Disclaimer

This document serves as a quick summary of the lesson and may not encompass the entirety of the content discussed. It is intended to provide a brief overview and should be considered merely as a reference to contextualize the exercises. For a comprehensive understanding of all topics, concepts, and discussions, referring to the full lesson material is recommended.

## Summary

In the first lesson, the target was getting an understanding of the essential 
prerequisites for establishing a secure web system, particularly focusing on an 
internet-facing banking system that provides a private area for each user. 
The goal was to outline the foundational requirements needed to ensure the security 
and reliability of such a system. 

### Prerequisites for a Secure Web System:

1. **Confidentiality**: Ensuring that sensitive information is accessible only to those authorized to view it.
2. **Integrity**: Guaranteeing that the data is accurate and untampered, maintaining its correctness throughout its lifecycle.
3. **Availability**: Ensuring the system and its data are available to authorized users when needed, which is crucial for maintaining trust and operational continuity.
4. **Authentication**: Verifying the identity of all parties involved, including users and the bank itself, to prevent unauthorized access.
5. **Robust SSL/TLS**: Implementing strong encryption protocols to establish encrypted links between the server and client, protecting data in transit.
6. **Segregation of Responsibilities**: Dividing responsibilities among different roles or components to minimize risk and prevent unauthorized access or actions within the system.
7. **No Need for a Secure Channel to Exchange Keys**: Eliminating the requirement for a pre-established secure channel for key exchange, effectively removing the paradox "We need a secure channel to establish a secure channel".
8. **Low Number of Keys**: Keeping the number of cryptographic keys to a minimum to simplify management and reduce security risks.
9. **Speed**: Ensuring the system operates efficiently without compromising security, which is critical for user satisfaction and operational effectiveness.
10. **Non-repudiation**: Providing proof of the origin and integrity of data, preventing any party from denying the authenticity of their transactions or communications.

### Major Approaches Developed:

- **Symmetric Encryption**: Involves using the same key for both encryption and decryption. It addresses confidentiality, integrity, the robustness of SSL, and speed. However, it falls short in other areas, particularly because it requires secure key exchange and doesn't inherently support authentication, non-repudiation, or segregation of responsibilities.
- **Asymmetric Encryption**: Utilizes a pair of keys (public and private) for encryption and decryption, respectively. This approach effectively covers confidentiality, integrity, authentication, SSL robustness, and non-repudiation (to some extent, segregation of responsibilities). However, it struggles with the need for a low number of keys and does not eliminate the need for a secure channel for key exchange, affecting speed due to its computational demands.
- **Public Key Infrastructure (PKI)**: This method overcomes the limitations of both symmetric and asymmetric encryption by introducing a trusted authority that certifies the identities associated with public keys. PKI comprehensively addresses all the prerequisites by:
    - Ensuring confidentiality through encrypted communications.
    - Maintaining integrity by using digital signatures.
    - Authenticating parties through certificates.
    - Robust encryption is guaranteed by asymmetric encryption.
    - Segregating responsibilities via certificate authorities (CAs) and registration authorities (RAs) roles.
    - Facilitating key management without the need for a pre-established secure channel for key exchange.
    - Reducing the complexity associated with key management by leveraging public key cryptography for a wide range of users.
    - Offering efficient mechanisms for verifying certificates and encrypting data, thus addressing speed concerns.
    - Providing non-repudiation through the use of digital certificates and signatures, ensuring that entities cannot deny their involvement in a transaction.

### Conclusion

The lesson concluded with an in-depth discussion on how PKI effectively solves the 
highlighted issues by relying on a trusted authority to certify the identities of the 
actors associated with certain public keys. 

## Exercise

The exercise is to write a script to creat a SSL Certificate Authority and issue server
certificates. 

### Solutions

Three solutions are provided:
* Standalone Bash Script using openssl library [ex01.sh](standalone/ex01.sh)
* Standalone Windows PowerShell script using standard Windows cmdlets [ex01.ps1](standalone/ex01.ps1)
* Python solution [ca-manager.py](ca-manager.py), implementing:
  * A Bash Wrapper
  * A PowerShell Wrapper
  * A native Python solution

All the solutions will read the content of the `config/config.ini` file and generate 
certificates accordingly.

All the certificates will be generated in the `certs` directory.
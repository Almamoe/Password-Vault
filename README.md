# Password-Vault

# **Secure Password Vault**

## **Overview**
The **Password Vault** is a secure application designed to store, manage, and retrieve passwords for various accounts in a centralized and encrypted database. The primary focus is on ensuring the privacy and security of user data by using cryptographic techniques to protect sensitive information.

> **Note**: This project is still in progress. The goal is to transform it into a fully functional application that users can easily install and use.

---

## **Features**
- **User Authentication**:
  - Secure master password protection.
  - Master passwords are hashed and never stored in plaintext.
- **Password Management**:
  - Add, retrieve, update, and delete account credentials.
  - View stored accounts in a user-friendly format.
- **Enhanced Security**:
  - Passwords are hashed using secure algorithms (e.g., SHA-256).
  - Recovery key support for account recovery.
- **User-Friendly Interface**:
  - Simple command-line interface for interacting with the vault (future plans include a GUI).

---

## **Technologies Used**
- **Programming Language**: Python
- **Database**: SQLite for lightweight and efficient password storage.
- **Cryptography**: 
  - Secure password hashing with Python’s `hashlib` library.
- **Development Tools**:
  - PyCharm for development and debugging.
  - Git for version control and collaboration.

---

## **Project Status**
This project is still in progress. Currently, it provides basic password management features through a command-line interface. Future updates will include:
- A graphical user interface (GUI) to enhance usability.
- Conversion into a standalone application for seamless user installation.
- Additional security features such as two-factor authentication (2FA) and encrypted cloud synchronization.

---

## **Challenges Faced**
- **Secure Storage**: Implemented SHA-256 hashing for master passwords and recovery keys to ensure data security.
- **Avoiding SQL Injection**: Used parameterized SQL queries to secure all database interactions.
- **Database Schema Issues**: Added schema verification during initialization to prevent runtime errors.

---

## **Future Enhancements**
- **Advanced Encryption**: Implement AES for password encryption instead of only hashing.
- **GUI Support**: Add a graphical user interface using Tkinter or PyQt for better usability.
- **Cloud Synchronization**: Enable secure cloud-based syncing to access the vault from multiple devices.
- **Password Generation**: Integrate a random password generator to create strong credentials.
- **Two-Factor Authentication (2FA)**: Enhance security by adding 2FA for vault access.

---

## **License**
This project is licensed under the MIT License. See the `LICENSE` file for details.

# WinSCP Password Decryptor | WinSCP 密码解密工具

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[English](#english) | [中文说明](#中文说明)

---

<a name="english"></a>
## 🇬🇧 English Description

A modern, user-friendly GUI tool built with Python (CustomTkinter) to recover stored session passwords from WinSCP configuration files (`WinSCP.ini`). 

This tool is particularly useful for IT administrators or users who have forgotten their server passwords but have them saved in WinSCP.

### ✨ Key Features
* **Modern UI:** Clean interface based on `CustomTkinter`.
* **Drag & Drop:** Simply drag your `WinSCP.ini` file into the window.
* **Bilingual Support:** Real-time switching between English and Chinese.
* **Security Decryption:** Implements the standard WinSCP password decryption algorithm.
* **CSV Export:** Export retrieved host, username, and password data to a CSV file.
* **Quick Copy:** Double-click any row to copy the password to the clipboard.

### 📦 Prerequisites
Ensure you have Python installed. You need to install the following dependencies:

```bash
pip install customtkinter tkinterdnd2
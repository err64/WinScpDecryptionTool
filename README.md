# WinSCP Password Decryptor (WinSCP 密码解密工具)

一个基于 Python 的现代化图形界面工具，用于从 `WinSCP.ini` 配置文件中快速恢复和解密保存的服务器密码。

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## ✨ 功能特点 (Features)

* **现代化 UI**: 使用 `CustomTkinter` 构建，支持系统深色/浅色模式，界面清新美观。
* **拖拽支持**: 直接将 `WinSCP.ini` 文件拖入窗口即可识别。
* **一键导出**: 支持将解密结果导出为 `.csv` 表格文件（Excel 可直接打开，无乱码）。
* **双语切换**: 内置中/英文实时切换功能。
* **双击复制**: 双击列表中的任意一行即可自动复制密码到剪贴板。
* **数据隐私**: 所有解密过程在本地完成，不上传任何数据。
import os
import csv
import configparser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk
from tkinterdnd2 import DND_FILES, TkinterDnD

# --- 语言包配置 ---
TRANSLATIONS = {
    "中": {
        "title": "WinSCP 密码解密工具",
        "subtitle": "将 WinSCP.ini 文件拖入下方或点击浏览",
        "placeholder": "请拖拽文件到这里，或粘贴路径...",
        "browse": "浏览文件",
        "decrypt": "开始解密",
        "export": "导出表格",
        "col_host": "主机 (Host)",
        "col_user": "用户名 (User)",
        "col_pass": "密码 (Password)",
        "msg_warn_path": "请先选择 WinSCP.ini 文件路径。",
        "msg_err_file": "找不到文件",
        "msg_err_read": "无法读取文件",
        "msg_info_none": "文件中未找到已加密的会话信息。",
        "msg_info_copied": "密码已复制到剪贴板",
        "msg_success_export": "导出成功！文件已保存至：",
        "msg_warn_no_data": "没有数据可导出，请先解密。",
        "status_ready": "就绪",
        "status_done": "解密完成，共找到 {} 条记录"
    },
    "EN": {
        "title": "WinSCP Password Decryptor",
        "subtitle": "Drag WinSCP.ini here or click Browse",
        "placeholder": "Drag file here or paste path...",
        "browse": "Browse",
        "decrypt": "Decrypt",
        "export": "Export CSV",
        "col_host": "Host",
        "col_user": "Username",
        "col_pass": "Password",
        "msg_warn_path": "Please select the WinSCP.ini file first.",
        "msg_err_file": "File not found",
        "msg_err_read": "Cannot read file",
        "msg_info_none": "No encrypted sessions found.",
        "msg_info_copied": "Password copied to clipboard",
        "msg_success_export": "Export successful! Saved to:",
        "msg_warn_no_data": "No data to export. Please decrypt first.",
        "status_ready": "Ready",
        "status_done": "Done. Found {} records."
    }
}


# ==========================================
# 核心解密逻辑 (保持不变)
# ==========================================
def decrypt_next_char(data):
    if len(data) <= 0:
        return 0, data
    a = data[0]
    b = data[1]
    data = data[2:]
    return ~(((a << 4) + b) ^ 0xA3) & 0xff, data


def decrypt_password(host, username, encrypted_pass):
    try:
        passbytes = [int(c, 16) for c in encrypted_pass]
        flag, passbytes = decrypt_next_char(passbytes)
        length = 0
        if flag == 0xFF:
            _, passbytes = decrypt_next_char(passbytes)
            length, passbytes = decrypt_next_char(passbytes)
        else:
            length = flag
        to_be_deleted, passbytes = decrypt_next_char(passbytes)
        passbytes = passbytes[to_be_deleted * 2:]
        clearpass = ""
        for _ in range(length):
            val, passbytes = decrypt_next_char(passbytes)
            clearpass += chr(val)
        key = username + host
        if flag == 0xFF:
            if clearpass.startswith(key):
                clearpass = clearpass[len(key):]
        return clearpass
    except Exception as e:
        return f"Error: {str(e)}"


# ==========================================
# 图形化界面 (GUI) 类
# ==========================================
class App(ctk.CTk, TkinterDnD.DnDWrapper):
    def __init__(self):
        super().__init__()
        self.TkdndVersion = TkinterDnD._require(self)

        # 设置默认语言
        self.lang = "中"
        self.text_res = TRANSLATIONS[self.lang]

        # 窗口基础设置
        self.title(self.text_res["title"])
        self.geometry("950x650")
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        # 布局权重
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self.setup_ui()
        self.update_ui_text()  # 初始化文本

    def setup_ui(self):
        # --- 1. 顶部区域 (标题 + 语言切换) ---
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")

        self.lbl_title = ctk.CTkLabel(
            self.header_frame,
            text="",  # 动态设置
            font=("Microsoft YaHei UI", 24, "bold")
        )
        self.lbl_title.pack(side="left")

        # 语言切换开关 (Segmented Button)
        self.lang_switch = ctk.CTkSegmentedButton(
            self.header_frame,
            values=["中", "EN"],
            command=self.change_language,
            width=100
        )
        self.lang_switch.set("中")
        self.lang_switch.pack(side="right")

        # 副标题
        self.lbl_subtitle = ctk.CTkLabel(
            self.header_frame,
            text="",
            text_color="gray",
            font=("Microsoft YaHei UI", 14)
        )


        self.subtitle_frame = ctk.CTkFrame(self, fg_color="transparent", height=20)
        self.subtitle_frame.grid(row=0, column=0, sticky="s", pady=(50, 0))  # Hacky layout adjustment
        self.lbl_subtitle.place(x=22, y=45)  # 绝对定位微调

        # --- 2. 输入与操作区域 ---
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        self.input_frame.grid_columnconfigure(0, weight=1)

        self.entry_path = ctk.CTkEntry(
            self.input_frame,
            placeholder_text="",
            height=40,
            font=("Consolas", 12)
        )
        self.entry_path.grid(row=0, column=0, padx=(20, 10), pady=20, sticky="ew")

        self.entry_path.drop_target_register(DND_FILES)
        self.entry_path.dnd_bind('<<Drop>>', self.drop_file)

        self.btn_browse = ctk.CTkButton(
            self.input_frame,
            text="",
            command=self.browse_file,
            width=100,
            height=40,
            font=("Microsoft YaHei UI", 12, "bold")
        )
        self.btn_browse.grid(row=0, column=1, padx=(0, 10), pady=20)

        self.btn_decrypt = ctk.CTkButton(
            self.input_frame,
            text="",
            command=self.start_decryption,
            fg_color="#2CC985", hover_color="#25A66E",
            width=120,
            height=40,
            font=("Microsoft YaHei UI", 12, "bold")
        )
        self.btn_decrypt.grid(row=0, column=2, padx=(0, 10), pady=20)

        self.btn_export = ctk.CTkButton(
            self.input_frame,
            text="",
            command=self.export_data,
            fg_color="#3B8ED0", hover_color="#36719F",  # 蓝色
            width=120,
            height=40,
            font=("Microsoft YaHei UI", 12, "bold")
        )
        self.btn_export.grid(row=0, column=3, padx=(0, 20), pady=20)

        # --- 3. 数据展示区域 ---
        self.result_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.result_frame.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="nsew")

        self.style = ttk.Style()
        self.style.theme_use("clam")

        bg_color = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkFrame"]["fg_color"])
        text_color = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkLabel"]["text_color"])
        field_bg = "#2b2b2b" if ctk.get_appearance_mode() == "Dark" else "#ffffff"

        self.style.configure("Treeview", background=field_bg, foreground=text_color,
                             fieldbackground=field_bg, rowheight=30, borderwidth=0, font=("Microsoft YaHei UI", 11))
        self.style.configure("Treeview.Heading", background="#1f6aa5", foreground="white",
                             font=("Microsoft YaHei UI", 12, "bold"), borderwidth=0)
        self.style.map("Treeview", background=[('selected', '#1f538d')])

        columns = ("host", "user", "password")
        self.tree = ttk.Treeview(self.result_frame, columns=columns, show="headings", selectmode="browse",
                                 style="Treeview")

        self.tree.column("host", width=300, anchor="w")
        self.tree.column("user", width=200, anchor="w")
        self.tree.column("password", width=200, anchor="w")

        self.scrollbar = ctk.CTkScrollbar(self.result_frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", self.on_tree_double_click)

        # --- 4. 状态栏 ---
        self.lbl_status = ctk.CTkLabel(self, text="Ready", anchor="w", padx=20)
        self.lbl_status.grid(row=3, column=0, sticky="ew", pady=(0, 5))

    def change_language(self, value):
        """切换语言并刷新界面"""
        self.lang = value
        self.text_res = TRANSLATIONS[self.lang]
        self.update_ui_text()

    def update_ui_text(self):
        """更新所有界面元素的文本"""
        self.title(self.text_res["title"])
        self.lbl_title.configure(text=self.text_res["title"])
        self.lbl_subtitle.configure(text=self.text_res["subtitle"])
        self.entry_path.configure(placeholder_text=self.text_res["placeholder"])
        self.btn_browse.configure(text=self.text_res["browse"])
        self.btn_decrypt.configure(text=self.text_res["decrypt"])
        self.btn_export.configure(text=self.text_res["export"])

        # 更新 Treeview 表头
        self.tree.heading("host", text=self.text_res["col_host"])
        self.tree.heading("user", text=self.text_res["col_user"])
        self.tree.heading("password", text=self.text_res["col_pass"])

        # 如果状态栏是就绪状态，也更新一下
        if "Ready" in self.lbl_status.cget("text") or "就绪" in self.lbl_status.cget("text"):
            self.lbl_status.configure(text=self.text_res["status_ready"])

    def drop_file(self, event):
        file_path = event.data
        if file_path.startswith('{') and file_path.endswith('}'):
            file_path = file_path[1:-1]
        self.entry_path.delete(0, tk.END)
        self.entry_path.insert(0, file_path)
        self.start_decryption()

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("INI Files", "*.ini"), ("All Files", "*.*")])
        if file_path:
            self.entry_path.delete(0, tk.END)
            self.entry_path.insert(0, file_path)

    def start_decryption(self):
        ini_file = self.entry_path.get().strip()
        if not ini_file:
            messagebox.showwarning("Info", self.text_res["msg_warn_path"])
            return
        if not os.path.exists(ini_file):
            messagebox.showerror("Error", f"{self.text_res['msg_err_file']}:\n{ini_file}")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        config = configparser.ConfigParser(interpolation=None, delimiters=('=',), strict=False)
        try:
            with open(ini_file, 'r', encoding='utf-8') as f:
                config.read_file(f)
        except:
            try:
                with open(ini_file, 'r', encoding='gbk') as f:
                    config.read_file(f)
            except Exception as e:
                messagebox.showerror("Error", f"{self.text_res['msg_err_read']}: {e}")
                return

        count = 0
        for section in config.sections():
            if config.has_option(section, 'HostName'):
                hostname = config.get(section, 'HostName', fallback='')
                username = config.get(section, 'UserName', fallback='')
                password = config.get(section, 'Password', fallback='')

                if hostname and password:
                    decoded_pass = decrypt_password(hostname, username, password)
                    self.tree.insert("", "end", values=(hostname, username, decoded_pass))
                    count += 1

        if count == 0:
            messagebox.showinfo("Info", self.text_res["msg_info_none"])
            self.lbl_status.configure(text=self.text_res["msg_info_none"])
        else:
            self.lbl_status.configure(text=self.text_res["status_done"].format(count))

    def export_data(self):
        """导出 Treeview 数据到 CSV"""
        # 获取所有数据
        rows = []
        for item_id in self.tree.get_children():
            rows.append(self.tree.item(item_id)['values'])

        if not rows:
            messagebox.showwarning("Warning", self.text_res["msg_warn_no_data"])
            return

        # 弹出保存对话框
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            initialfile="WinSCP_Passwords.csv"
        )

        if file_path:
            try:
                # 使用 utf-8-sig 编码
                with open(file_path, 'w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.writer(f)
                    # 写入表头
                    writer.writerow([self.text_res["col_host"], self.text_res["col_user"], self.text_res["col_pass"]])
                    # 写入数据
                    writer.writerows(rows)

                messagebox.showinfo("Success", f"{self.text_res['msg_success_export']}\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Export Failed: {str(e)}")

    def on_tree_double_click(self, event):
        item = self.tree.selection()
        if not item: return
        vals = self.tree.item(item, "values")
        pwd = vals[2]
        self.clipboard_clear()
        self.clipboard_append(pwd)
        messagebox.showinfo("Info", f"{self.text_res['msg_info_copied']}:\n{pwd}")


if __name__ == "__main__":
    app = App()
    app.mainloop()
import os
import psutil
import time
import datetime
import sqlite3
import getpass
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk

# --- CONFIG ---
SENSITIVE_DIRS = ["C:/Users/Public/Documents", "C:/ImportantData"]
WORK_HOURS = (9, 18)
DB_FILE = "insider_threat_logs.db"

# --- DATABASE SETUP ---
def setup_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                      timestamp TEXT,
                      username TEXT,
                      event_type TEXT,
                      details TEXT)''')
    conn.commit()
    conn.close()

# --- GUI CLASS ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Config
        self.title("Insider Threat Detection Tool")
        self.geometry("1000x580")

        # Data Structures
        self.recent_logs = {} 
        self.alert_cooldowns = {"hours": 0, "usb": 0}

        # Grid Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- SIDEBAR ---
        self.sidebar_frame = ctk.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1) # Adjusted weight for spacing

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="INTD Tool", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.start_button = ctk.CTkButton(self.sidebar_frame, text="▶ Start Monitor", command=self.start_monitoring_thread)
        self.start_button.grid(row=1, column=0, padx=20, pady=10)

        self.refresh_button = ctk.CTkButton(self.sidebar_frame, text="🔄 Refresh Logs", command=self.refresh_logs)
        self.refresh_button.grid(row=2, column=0, padx=20, pady=10)

        # NEW: Clear Logs Button
        self.clear_button = ctk.CTkButton(self.sidebar_frame, text="🗑️ Clear Logs", 
                                          fg_color="#c0392b", hover_color="#e74c3c", # Red color for danger
                                          command=self.clear_logs)
        self.clear_button.grid(row=3, column=0, padx=20, pady=10)

        self.appearance_mode_label = ctk.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=6, column=0, padx=20, pady=(10, 0))
        
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(self.sidebar_frame, values=["Light", "Dark", "System"],
                                                                       command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=7, column=0, padx=20, pady=(10, 20))
        self.appearance_mode_optionemenu.set("Dark")

        # --- MAIN CONTENT ---
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.header_label = ctk.CTkLabel(self.main_frame, text="Live System Activity Logs", font=ctk.CTkFont(size=18))
        self.header_label.grid(row=0, column=0, sticky="w", pady=(0, 10))

        # Treeview
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        columns = ("Timestamp", "User", "Event Type", "Details")
        self.tree = ttk.Treeview(self.main_frame, columns=columns, show="headings")
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=160)
        
        self.tree.grid(row=1, column=0, sticky="nsew")
        
        self.scrollbar = ctk.CTkScrollbar(self.main_frame, orientation="vertical", command=self.tree.yview)
        self.scrollbar.grid(row=1, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        self.apply_treeview_style("Dark")
        setup_db()

    # --- NEW FUNCTION: CLEAR LOGS ---
    def clear_logs(self):
        # 1. Ask for confirmation
        if messagebox.askyesno("Clear Logs", "Are you sure you want to DELETE ALL logs?\nThis action cannot be undone."):
            try:
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                
                # 2. Execute the requested Drop command
                cursor.execute('DROP TABLE IF EXISTS logs')
                
                conn.commit()
                conn.close()
                
                # 3. Re-create the table immediately (so the monitor thread doesn't crash)
                setup_db()
                
                # 4. Clear the GUI list
                self.refresh_logs()
                
                messagebox.showinfo("Success", "All logs have been cleared.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear logs: {e}")

    # --- LOGGING & MONITORING ---
    def log_event_smart(self, event_type, details):
        current_time = time.time()
        key = (event_type, details)

        if key in self.recent_logs:
            if current_time - self.recent_logs[key] < 60:
                return 

        self.recent_logs[key] = current_time
        human_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO logs VALUES (?, ?, ?, ?)",
                        (human_time, getpass.getuser(), event_type, details))
            conn.commit()
            conn.close()
        except sqlite3.OperationalError:
            # Handle rare case where table is being dropped while writing
            pass

    def monitor_file_access(self):
        access_count = 0
        for dir_path in SENSITIVE_DIRS:
            if os.path.exists(dir_path):
                for root, dirs, files in os.walk(dir_path):
                    for file in files:
                        path = os.path.join(root, file)
                        try:
                            access_time = os.path.getatime(path)
                            if time.time() - access_time < 60:
                                self.log_event_smart("File Access", f"Accessed: {path}")
                                access_count += 1
                        except Exception:
                            pass
        if access_count > 3:
            self.trigger_alert("High Alert", f"{access_count} sensitive files accessed recently!")

    def monitor_working_hours(self):
        current_hour = datetime.datetime.now().hour
        if current_hour < WORK_HOURS[0] or current_hour >= WORK_HOURS[1]:
            self.log_event_smart("Off-hour Access", f"System active at {current_hour}:00")
            if time.time() - self.alert_cooldowns["hours"] > 300:
                self.trigger_alert("Security Alert", "User login detected outside working hours!")
                self.alert_cooldowns["hours"] = time.time()

    def monitor_usb_devices(self):
        drives = [d.device for d in psutil.disk_partitions() if 'removable' in d.opts]
        for drive in drives:
            self.log_event_smart("USB Inserted", f"Drive: {drive}")
        if len(drives) > 0:
            if time.time() - self.alert_cooldowns["usb"] > 60:
                self.trigger_alert("Physical Security", "USB Device Detected!")
                self.alert_cooldowns["usb"] = time.time()

    def monitor_suspicious_processes(self):
        suspicious = ["cmd.exe", "powershell.exe", "taskkill.exe"]
        suspicious_count = 0
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() in suspicious:
                    self.log_event_smart("Suspicious Process", f"Process: {proc.info['name']} (PID: {proc.info['pid']})")
                    suspicious_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if suspicious_count > 5:
            self.trigger_alert("Critical Alert", f"{suspicious_count} suspicious processes running!")

    # --- GUI UTILS ---
    def trigger_alert(self, title, message):
        self.after(0, lambda: messagebox.showwarning(title, message))

    def refresh_logs(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        
        # Check if table exists (in case it was just dropped and setup_db failed)
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100")
            for row in cursor.fetchall():
                self.tree.insert("", "end", values=row)
            conn.close()
        except sqlite3.OperationalError:
            pass # Table might not exist yet

    def apply_treeview_style(self, mode):
        if mode == "Dark":
            bg, fg, h_bg, h_fg = "#2b2b2b", "white", "#343638", "white"
        else:
            bg, fg, h_bg, h_fg = "white", "black", "#e1e1e1", "black"

        self.style.configure("Treeview", background=bg, foreground=fg, fieldbackground=bg, borderwidth=0)
        self.style.configure("Treeview.Heading", background=h_bg, foreground=h_fg, relief="flat")
        self.style.map("Treeview", background=[('selected', '#1f538d')])

    def change_appearance_mode_event(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)
        self.apply_treeview_style(new_appearance_mode)

    def start_monitoring_thread(self):
        messagebox.showinfo("Insider Threat Tool", "Monitoring started. Updates every 5s.")
        def run_loop():
            while True:
                self.monitor_file_access()
                self.monitor_working_hours()
                self.monitor_usb_devices()
                self.monitor_suspicious_processes()
                self.after(0, self.refresh_logs)
                time.sleep(5)
        threading.Thread(target=run_loop, daemon=True).start()

if __name__ == "__main__":
    app = App()
    app.mainloop()

import customtkinter as ctk
import datetime
import threading
import queue
from typing import List, Dict, Any
from monitor.collector import collect_processes
from monitor.heuristics import score_process
from monitor.logger import log_threat

class ProcessDetailPopup(ctk.CTkToplevel):
    def __init__(self, master, proc_data, score, level, triggered_rules, **kwargs):
        super().__init__(master, **kwargs)
        self.title(f"Detail: {proc_data['name']}")
        self.geometry("600x520")
        self.attributes("-topmost", True)
        
        colors = {
            "SAFE": "#00ff88",
            "SUSPICIOUS": "#ffd700",
            "DANGEROUS": "#ff8c00",
            "CRITICAL": "#ff2222"
        }
        level_color = colors.get(level, "#ffffff")
        
        heading_frame = ctk.CTkFrame(self, fg_color="transparent")
        heading_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(
            heading_frame, 
            text=f"{proc_data['name']} (PID: {proc_data['pid']})", 
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=level_color
        ).pack(side="left")
        
        details_frame = ctk.CTkFrame(self)
        details_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        def add_detail(label, value):
            row = ctk.CTkFrame(details_frame, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=5)
            ctk.CTkLabel(row, text=f"{label}:", font=ctk.CTkFont(weight="bold"), width=120, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=str(value), wraplength=400, anchor="w", justify="left").pack(side="left", fill="x", expand=True)

        add_detail("Path", proc_data.get('path') or "Unknown")
        add_detail("Parent", f"{proc_data.get('parent_name')} (PID: {proc_data.get('parent_pid')})" if proc_data.get('parent_name') else "None")
        add_detail("Remote IPs", ", ".join(proc_data.get('remote_ips', [])) or "None")
        add_detail("Threat Score", f"{score} ({level})")
        
        ctk.CTkLabel(details_frame, text="Triggered Rules:", font=ctk.CTkFont(weight="bold"), anchor="w").pack(fill="x", padx=10, pady=(10, 5))
        
        rules_frame = ctk.CTkScrollableFrame(details_frame, height=150)
        rules_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        if not triggered_rules:
            ctk.CTkLabel(rules_frame, text="No suspicious rules triggered.").pack(anchor="w", padx=5)
        else:
            for i, rule in enumerate(triggered_rules, 1):
                ctk.CTkLabel(rules_frame, text=f"{i}. {rule}", anchor="w", justify="left").pack(fill="x", padx=5, pady=2)

class ProcessRow:
    """Helper class to manage individual process rows with Material 3 styling"""
    def __init__(self, master, click_callback):
        self.frame = ctk.CTkFrame(master, corner_radius=12, border_width=1, border_color="#333333")
        self.labels = []
        self.click_callback = click_callback
        self.data = None
        self.last_values = []
        self.last_level = None
        
        # PID 80, Name 240, CPU 100, Mem 120, Conn 120, Level 150
        widths = [80, 240, 100, 120, 120, 150]
        # Container for horizontal layout within the rounded frame
        self.inner_frame = ctk.CTkFrame(self.frame, fg_color="transparent")
        self.inner_frame.pack(fill="x", padx=10, pady=5)
        
        for w in widths:
            lbl = ctk.CTkLabel(self.inner_frame, text="", width=w, font=ctk.CTkFont(size=13))
            lbl.pack(side="left", padx=5, pady=2)
            lbl.bind("<Button-1>", self._on_click)
            self.labels.append(lbl)
            
        self.frame.bind("<Button-1>", self._on_click)
        self.inner_frame.bind("<Button-1>", self._on_click)
        
    def _on_click(self, event):
        if self.data:
            self.click_callback(self.data)
            
    def update(self, data):
        self.data = data
        p = data['proc']
        level = data['level']
        
        mem_mb = f"{p['memory'] / 1024 / 1024:.1f}"
        values = [str(p['pid']), p['name'], f"{p['cpu']}%", mem_mb, str(p['connection_count']), level]
        
        if values == self.last_values and level == self.last_level:
            return
            
        self.last_values = values
        self.last_level = level
        
        # Material 3 inspired dark palette
        # Backgrounds: deeper hues
        row_bg_colors = {
            "SAFE": "#1A2E2A",      # Deep Teal
            "SUSPICIOUS": "#2E2A1A", # Dark Olive/Gold
            "DANGEROUS": "#2E1F1A",  # Deep Copper
            "CRITICAL": "#2E1A1A"    # Deep Wine
        }
        # Text colors: brighter, more pastel (M3 Dark style)
        text_colors = {
            "SAFE": "#B4EBC8",      # Light Mint
            "SUSPICIOUS": "#F9D672", # Soft Gold
            "DANGEROUS": "#FFB74D",  # Pastel Orange
            "CRITICAL": "#F2B8B5"    # Soft Pink/Red
        }
        
        self.frame.configure(fg_color=row_bg_colors.get(level, "#1C1B1F"))
        self.frame.configure(border_color="#49454F" if level != "SAFE" else "#333333")
        
        for i, val in enumerate(values):
            color = text_colors.get(level) if i == 5 else "#E6E1E5"
            self.labels[i].configure(text=val, text_color=color)
            if i == 1: # Name
                self.labels[i].configure(font=ctk.CTkFont(size=13, weight="bold"))
            
    def show(self):
        self.frame.pack(fill="x", pady=4, padx=10)
        
    def hide(self):
        self.frame.pack_forget()

    def destroy(self):
        self.frame.destroy()

class DashboardApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("Prodot")
        self.geometry("1100x650")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        
        # Internal state
        self.pid_rows = {}
        self.data_queue = queue.Queue()
        self.is_refreshing = False
        
        # Global Style Overrides
        self.configure(fg_color="#1C1B1F") # M3 Deep Surface
        
        # Header (Large M3 Style)
        self.header = ctk.CTkFrame(self, height=100, corner_radius=0, fg_color="#262529")
        self.header.pack(fill="x", side="top")
        
        self.title_label = ctk.CTkLabel(
            self.header, 
            text="🛡️ Prodot Monitor", 
            font=ctk.CTkFont(size=28, weight="bold", family="Inter")
        )
        self.title_label.pack(side="left", padx=(40, 20), pady=25)
        
        self.scan_time_label = ctk.CTkLabel(self.header, text="Ready", font=ctk.CTkFont(size=14))
        self.scan_time_label.pack(side="left", padx=20)
        
        self.status_label = ctk.CTkLabel(self.header, text="Idle", text_color="#A0A0A0", font=ctk.CTkFont(size=12))
        self.status_label.pack(side="left", padx=10)
        
        self.refresh_button = ctk.CTkButton(
            self.header, 
            text="Refresh Scan", 
            corner_radius=20,
            fg_color="#D0BCFF", # M3 Primary
            text_color="#381E72",
            hover_color="#E8DEF8",
            width=140,
            height=40,
            font=ctk.CTkFont(weight="bold"),
            command=self.manual_refresh
        )
        self.refresh_button.pack(side="right", padx=40)
        
        # Table Header
        self.table_header = ctk.CTkFrame(self, fg_color="transparent")
        self.table_header.pack(fill="x", padx=30, pady=(20, 10))
        
        cols = [("PID", 80), ("Process Name", 240), ("CPU %", 100), ("Memory MB", 120), ("Connections", 120), ("Threat Level", 150)]
        for text, width in cols:
            lbl = ctk.CTkLabel(self.table_header, text=text, width=width, font=ctk.CTkFont(size=12, weight="bold"), text_color="#CAC4D0")
            lbl.pack(side="left", padx=5)
            
        # Table Container
        self.scroll_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        self.after(100, self.check_queue)
        self.manual_refresh()

    def manual_refresh(self):
        if self.is_refreshing:
            return
        self.is_refreshing = True
        self.status_label.configure(text="Scanning System...", text_color="#D0BCFF")
        threading.Thread(target=self.background_collector, daemon=True).start()

    def background_collector(self):
        try:
            raw_processes = collect_processes()
            scored_data = []
            for p in raw_processes:
                score, level, rules = score_process(p)
                scored_data.append({'proc': p, 'score': score, 'level': level, 'rules': rules})
                if level in ["SUSPICIOUS", "DANGEROUS", "CRITICAL"]:
                    log_threat(p, score, level, rules)
            
            scored_data.sort(key=lambda x: x['score'], reverse=True)
            self.data_queue.put(scored_data)
        except Exception as e:
            print(f"Collection error: {e}")
            self.data_queue.put(None)

    def check_queue(self):
        try:
            while True:
                data = self.data_queue.get_nowait()
                if data is not None:
                    self.render_data(data)
                
                self.is_refreshing = False
                self.status_label.configure(text="System Clean", text_color="#B4EBC8")
                self.after(15000, self.manual_refresh)
        except queue.Empty:
            pass
        self.after(100, self.check_queue)

    def render_data(self, scored_data):
        scored_data = scored_data[:300]
        new_pids = {data['proc']['pid'] for data in scored_data}
        
        current_rows_pids = list(self.pid_rows.keys())
        for pid in current_rows_pids:
            if pid not in new_pids:
                self.pid_rows[pid].destroy()
                del self.pid_rows[pid]
            
        for data in scored_data:
            pid = data['proc']['pid']
            if pid not in self.pid_rows:
                self.pid_rows[pid] = ProcessRow(self.scroll_frame, self.show_detail)
            
            self.pid_rows[pid].update(data)
            self.pid_rows[pid].show()
            
        now = datetime.datetime.now().strftime("%I:%M %p")
        self.scan_time_label.configure(text=f"Last Scan: {now}", text_color="#E6E1E5")

    def show_detail(self, data):
        popup = ProcessDetailPopup(self, data['proc'], data['score'], data['level'], data['rules'])
        popup.focus()

if __name__ == "__main__":
    app = DashboardApp()
    app.mainloop()

if __name__ == "__main__":
    app = DashboardApp()
    app.mainloop()

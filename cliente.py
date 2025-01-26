import tkinter as tk
from tkinter import ttk, messagebox
import socket
import os
import requests
import json

class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RDP Client Manager")
        self.root.configure(bg="#2E2E2E")  

        self.config_file = "client_config.json"
        self.connections_file = "connections.json"
        self.server_ip, self.connections = self.load_config()

        self.title_label = tk.Label(root, text="RDP Client Manager", font=("Arial", 16), fg="white", bg="#2E2E2E")
        self.title_label.pack(pady=10)

        self.server_frame = tk.Frame(root, bg="#2E2E2E")
        self.server_frame.pack(pady=5)

        tk.Label(self.server_frame, text="Server IP:", fg="white", bg="#2E2E2E").pack(side="left", padx=5)
        self.server_entry = tk.Entry(self.server_frame, relief="flat", highlightbackground="#1E90FF", highlightcolor="#1E90FF", highlightthickness=1)
        self.server_entry.pack(side="left", padx=5)
        self.server_entry.insert(0, self.server_ip)

        self.save_ip_var = tk.BooleanVar()
        self.save_ip_check = tk.Checkbutton(self.server_frame, text="Save IP", variable=self.save_ip_var, bg="#2E2E2E", fg="white", selectcolor="#1E90FF")
        self.save_ip_check.pack(side="left", padx=5)

        connect_button = tk.Button(self.server_frame, text="Connect", command=self.register_client, bg="#1E90FF", fg="white", relief="raised", borderwidth=3)
        connect_button.pack(side="left", padx=5)

        self.table_frame = tk.Frame(root, bg="#2E2E2E")
        self.table_frame.pack(pady=10, padx=10, fill="both", expand=True)

        self.tree = ttk.Treeview(self.table_frame, columns=("Name", "IP", "Port", "Status"), show="headings")
        self.tree.heading("Name", text="Computer Name")
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("Port", text="Port")
        self.tree.heading("Status", text="Status")

        self.scrollbar = ttk.Scrollbar(self.table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)

        self.tree.bind("<Double-1>", self.on_double_click)

        self.button_frame = tk.Frame(root, bg="#2E2E2E")
        self.button_frame.pack(pady=10)

        add_button = tk.Button(self.button_frame, text="Add", command=self.add_entry, bg="#1E90FF", fg="white", relief="raised", borderwidth=3)
        add_button.pack(side="left", padx=5)

        edit_button = tk.Button(self.button_frame, text="Edit", command=self.edit_entry, bg="#1E90FF", fg="white", relief="raised", borderwidth=3)
        edit_button.pack(side="left", padx=5)

        remove_button = tk.Button(self.button_frame, text="Remove", command=self.remove_entry, bg="#1E90FF", fg="white", relief="raised", borderwidth=3)
        remove_button.pack(side="left", padx=5)

        refresh_button = tk.Button(self.button_frame, text="Refresh", command=self.refresh_status, bg="#1E90FF", fg="white", relief="raised", borderwidth=3)
        refresh_button.pack(side="left", padx=5)

        self.populate_table()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def load_config(self):
        try:
            with open(self.config_file, "r") as f:
                config = json.load(f)
                server_ip = config.get("server_ip", "127.0.0.1")
        except FileNotFoundError:
            server_ip = "127.0.0.1"

        try:
            with open(self.connections_file, "r") as f:
                connections = json.load(f)
  
                if not isinstance(connections, list) or not all(isinstance(conn, dict) for conn in connections):
                    raise ValueError("Invalid connections format")
        except (FileNotFoundError, ValueError):
            connections = [
                {"name": "Computer-1", "ip": "192.168.1.10", "port": "3389", "status": "Checking..."},
                {"name": "Computer-2", "ip": "192.168.1.20", "port": "3389", "status": "Checking..."}
            ]

        return server_ip, connections

    def save_config(self):
        config = {"server_ip": self.server_entry.get()}
        with open(self.config_file, "w") as f:
            json.dump(config, f)

        with open(self.connections_file, "w") as f:
            json.dump(self.connections, f, indent=4)

    def register_client(self):
        self.server_ip = self.server_entry.get()
        client_data = {
            "name": socket.gethostname(),
            "rdps": self.connections
        }
        try:
            response = requests.post(f"http://{self.server_ip}:443/register_client", json=client_data)
            if response.status_code == 200:
                messagebox.showinfo("Success", "Registered successfully with the server!")
                self.save_config()
            else:
                messagebox.showerror("Error", "Failed to register with server.")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Connection error: {e}")

    def populate_table(self):
        self.tree.delete(*self.tree.get_children())
        for conn in self.connections:
            self.tree.insert("", "end", values=(conn["name"], conn["ip"], conn["port"], conn["status"]))

    def refresh_status(self):
        for item in self.tree.get_children():
            values = self.tree.item(item, "values")
            name, ip, port, _ = values
            new_status = self.check_connection(ip, port)
            self.tree.item(item, values=(name, ip, port, new_status))

    def check_connection(self, ip, port):
        try:
            with socket.create_connection((ip, int(port)), timeout=5):
                return "Open"
        except socket.timeout:
            return "Closed (Timeout)"
        except Exception as e:
            return f"Closed ({e})"

    def add_entry(self):
        self.open_entry_window("Add Entry", None)

    def edit_entry(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select an entry to edit")
            return
        item = self.tree.item(selected_item[0])
        self.open_entry_window("Edit Entry", {"id": selected_item[0], "values": item["values"]})

    def remove_entry(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select an entry to remove")
            return
        for sel in selected_item:
            self.tree.delete(sel)
        self.connections = [
            {"name": self.tree.item(child, "values")[0],
             "ip": self.tree.item(child, "values")[1],
             "port": self.tree.item(child, "values")[2],
             "status": self.tree.item(child, "values")[3]}
            for child in self.tree.get_children()
        ]

    def open_entry_window(self, title, item):
        window = tk.Toplevel(self.root)
        window.title(title)
        window.configure(bg="#2E2E2E")

        tk.Label(window, text="Computer Name:", fg="white", bg="#2E2E2E").grid(row=0, column=0, padx=10, pady=5)
        name_entry = tk.Entry(window, relief="flat", highlightbackground="#1E90FF", highlightcolor="#1E90FF", highlightthickness=1)
        name_entry.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(window, text="IP Address:", fg="white", bg="#2E2E2E").grid(row=1, column=0, padx=10, pady=5)
        ip_entry = tk.Entry(window, relief="flat", highlightbackground="#1E90FF", highlightcolor="#1E90FF", highlightthickness=1)
        ip_entry.grid(row=1, column=1, padx=10, pady=5)

        tk.Label(window, text="Port:", fg="white", bg="#2E2E2E").grid(row=2, column=0, padx=10, pady=5)
        port_entry = tk.Entry(window, relief="flat", highlightbackground="#1E90FF", highlightcolor="#1E90FF", highlightthickness=1)
        port_entry.grid(row=2, column=1, padx=10, pady=5)

        if item:
            name_entry.insert(0, item['values'][0])
            ip_entry.insert(0, item['values'][1])
            port_entry.insert(0, item['values'][2])

        def save_entry():
            name = name_entry.get()
            ip = ip_entry.get()
            port = port_entry.get()
            if not name or not ip or not port:
                messagebox.showerror("Error", "All fields are required")
                return

            if item:
                self.tree.item(item["id"], values=(name, ip, port, self.check_connection(ip, port)))
            else:
                self.tree.insert("", "end", values=(name, ip, port, self.check_connection(ip, port)))

            self.connections = [
                {"name": self.tree.item(child, "values")[0],
                 "ip": self.tree.item(child, "values")[1],
                 "port": self.tree.item(child, "values")[2],
                 "status": self.tree.item(child, "values")[3]}
                for child in self.tree.get_children()
            ]
            window.destroy()

        save_button = tk.Button(window, text="Save", command=save_entry, bg="#1E90FF", fg="white", relief="raised", borderwidth=3)
        save_button.grid(row=3, column=0, columnspan=2, pady=10)

    def on_double_click(self, event):
        selected_item = self.tree.selection()
        if not selected_item:
            return
        item = self.tree.item(selected_item[0])
        ip = item["values"][1]
        port = item["values"][2]
        os.system(f"mstsc /v:{ip}:{port}")

    def on_close(self):
        self.save_config()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()

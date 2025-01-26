import tkinter as tk
from tkinter import ttk, messagebox
from flask import Flask, jsonify, request
import threading
import json
import requests

app = Flask(__name__)

server_data = {
    "clients": {}, 
    "config": {
        "server_ip": "127.0.0.1"
    }
}

@app.route('/register_client', methods=['POST'])
def register_client():
    client_data = request.json
    client_ip = request.remote_addr
    server_data["clients"][client_ip] = client_data
    return jsonify({"message": "Client registered", "client_ip": client_ip}), 200

@app.route('/get_clients', methods=['GET'])
def get_clients():
    return jsonify(server_data["clients"]), 200

@app.route('/get_rdps/<client_ip>', methods=['GET'])
def get_rdps(client_ip):
    client = server_data["clients"].get(client_ip)
    if not client:
        return jsonify({"error": "Client not found"}), 404
    return jsonify(client.get("rdps", [])), 200

@app.route('/update_rdps/<client_ip>', methods=['POST'])
def update_rdps(client_ip):
    new_rdps = request.json
    if client_ip not in server_data["clients"]:
        return jsonify({"error": "Client not found"}), 404
    server_data["clients"][client_ip]["rdps"] = new_rdps
    return jsonify({"message": "RDPs updated"}), 200


def run_server():
    app.run(host=server_data["config"]["server_ip"], port=443, debug=False)

server_thread = threading.Thread(target=run_server)
server_thread.daemon = True
server_thread.start()


class ServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RDP Server Manager")


        self.ip_frame = tk.Frame(root)
        self.ip_frame.pack(pady=10)

        tk.Label(self.ip_frame, text="Server IP:").pack(side="left", padx=5)
        self.ip_entry = tk.Entry(self.ip_frame)
        self.ip_entry.pack(side="left", padx=5)
        self.ip_entry.insert(0, server_data["config"]["server_ip"])

        tk.Button(self.ip_frame, text="Save", command=self.save_server_ip).pack(side="left", padx=5)


        self.table_frame = tk.Frame(root)
        self.table_frame.pack(pady=10, padx=10, fill="both", expand=True)

        self.tree = ttk.Treeview(self.table_frame, columns=("IP", "Clients", "RDPs"), show="headings")
        self.tree.heading("IP", text="Client IP")
        self.tree.heading("Clients", text="Clients Connected")
        self.tree.heading("RDPs", text="RDP Configurations")

        self.scrollbar = ttk.Scrollbar(self.table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)

        self.tree.bind("<Double-1>", self.on_double_click)

        self.refresh_button = tk.Button(root, text="Refresh Clients", command=self.refresh_clients)
        self.refresh_button.pack(pady=5)

        self.refresh_clients()

    def save_server_ip(self):
        new_ip = self.ip_entry.get()
        if new_ip:
            server_data["config"]["server_ip"] = new_ip
            messagebox.showinfo("Success", "Server IP updated successfully!")

    def refresh_clients(self):
        self.tree.delete(*self.tree.get_children())
        for ip, data in server_data["clients"].items():
            rdps = len(data.get("rdps", []))
            self.tree.insert("", "end", values=(ip, data.get("name", "Unknown"), rdps))

    def on_double_click(self, event):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "No client selected.")
            return

        item = self.tree.item(selected_item[0])
        client_ip = item['values'][0] if item['values'] else None
        if not client_ip:
            messagebox.showerror("Error", "Invalid client IP.")
            return

        self.open_client_editor(client_ip)

    def open_client_editor(self, client_ip):
        client_data = server_data["clients"].get(client_ip)
        if not client_data:
            messagebox.showerror("Error", "Client data not found.")
            return

        window = tk.Toplevel(self.root)
        window.title(f"Edit Client: {client_ip}")

        tk.Label(window, text="Computer Name:").grid(row=0, column=0, padx=10, pady=5)
        name_entry = tk.Entry(window)
        name_entry.grid(row=0, column=1, padx=10, pady=5)
        name_entry.insert(0, client_data.get("name", ""))

        tk.Label(window, text="RDPs:").grid(row=1, column=0, padx=10, pady=5)
        rdps_entry = tk.Text(window, height=10, width=40)
        rdps_entry.grid(row=1, column=1, padx=10, pady=5)
        rdps_entry.insert("1.0", json.dumps(client_data.get("rdps", []), indent=2))

        def save_client():
            new_name = name_entry.get()
            try:
                new_rdps = json.loads(rdps_entry.get("1.0", "end-1c"))
                client_data["name"] = new_name
                client_data["rdps"] = new_rdps

                # Send update to client
                try:
                    response = requests.post(f"http://{client_ip}:443/update_rdps/{client_ip}", json=new_rdps)
                    if response.status_code == 200:
                        messagebox.showinfo("Success", "Client data updated successfully!")
                        self.refresh_clients()
                        window.destroy()
                    else:
                        messagebox.showerror("Error", "Failed to update client remotely.")
                except requests.exceptions.RequestException as e:
                    messagebox.showerror("Error", f"Error updating client: {e}")
            except json.JSONDecodeError:
                messagebox.showerror("Error", "Invalid RDP data format. Must be JSON.")

        tk.Button(window, text="Save", command=save_client).grid(row=2, column=0, columnspan=2, pady=10)


if __name__ == "__main__":
    root = tk.Tk()
    app = ServerApp(root)
    root.mainloop()

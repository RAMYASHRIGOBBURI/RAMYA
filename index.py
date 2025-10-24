import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from urllib.parse import urlparse


# ---------- Helper functions ----------

def resolve_host(host):
    """Convert URL/hostname to IP. Returns IP string or None on error."""
    try:
        parsed = urlparse(host)
        if parsed.scheme:
            host = parsed.netloc
        return socket.gethostbyname(host)
    except Exception as e:
        messagebox.showerror("Resolve Error", f"Could not resolve host:\n{e}")
        return None


def guess_service(port, proto):
    """Return a human-friendly service name for port/proto if available."""
    try:
        return socket.getservbyport(port, proto)
    except:
        return "Unknown"


def tcp_check(ip, port, timeout=0.6):
    """Return 'Open' or 'Closed' for a TCP port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.close()
        return "Open"
    except:
        return "Closed"


def udp_check(ip, port, timeout=0.6):
    """
    UDP scans are unreliable: send a small packet and wait for a response.
    If timeout, return 'Open|Filtered' (common), else 'Open' or 'Closed'.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b'\x00', (ip, port))
        s.recvfrom(1024)
        return "Open"
    except socket.timeout:
        return "Open|Filtered"
    except:
        return "Closed"
    finally:
        s.close()


# ---------- Scanning logic ----------

def parse_port_range(text):
    """Parse string like '1-1024' or '22,80,443' or '1-100,200,300-310'."""
    ports = set()
    parts = [p.strip() for p in text.split(",") if p.strip()]
    for p in parts:
        if "-" in p:
            a, b = p.split("-", 1)
            try:
                a = int(a); b = int(b)
                if a <= b:
                    ports.update(range(max(1, a), min(65535, b) + 1))
            except:
                continue
        else:
            try:
                val = int(p)
                if 1 <= val <= 65535:
                    ports.add(val)
            except:
                continue
    return sorted(ports)


def scan_ports(ip, ports, protocol, tree, progress, status_label, stop_event):
    """Scan the given ports and insert results into the treeview."""
    total = len(ports) * (1 if protocol in ("TCP", "UDP") else 2 if protocol == "Both" else 0)
    if total == 0:
        status_label.config(text="No ports to scan.")
        return

    done = 0
    for port in ports:
        if stop_event.is_set():
            status_label.config(text="Scan stopped.")
            return

        if protocol in ("TCP", "Both"):
            state = tcp_check(ip, port)
            service = guess_service(port, "tcp")
            tree.insert("", "end", values=(port, service, "TCP", state))
            done += 1
            progress["value"] = (done / total) * 100
            progress.update()

        if protocol in ("UDP", "Both"):
            state = udp_check(ip, port)
            service = guess_service(port, "udp")
            tree.insert("", "end", values=(port, service, "UDP", state))
            done += 1
            progress["value"] = (done / total) * 100
            progress.update()

    status_label.config(text="✅ Scan complete.")


# ---------- GUI callbacks ----------

def start_scan(host_entry, proto_choice, ports_entry, tree, progress, status_label, start_btn, stop_btn, stop_event):
    host = host_entry.get().strip()
    proto = proto_choice.get()
    port_text = ports_entry.get().strip()

    if not host:
        messagebox.showerror("Input Error", "Please enter a website/domain or IP address.")
        return

    ip = resolve_host(host)
    if not ip:
        return

    ports = parse_port_range(port_text)
    if not ports:
        messagebox.showerror("Input Error", "Enter a valid port range (e.g. 1-1024 or 22,80,443).")
        return

    # Clear previous results
    for i in tree.get_children():
        tree.delete(i)

    status_label.config(text=f"Scanning {ip} ({proto}) — {len(ports)} port(s)...")
    progress["value"] = 0
    start_btn["state"] = "disabled"
    stop_btn["state"] = "normal"
    stop_event.clear()

    # Run scan in background thread
    t = threading.Thread(
        target=lambda: (scan_ports(ip, ports, proto, tree, progress, status_label, stop_event),
                        start_btn.config(state="normal"),
                        stop_btn.config(state="disabled")),
        daemon=True,
    )
    t.start()


def stop_scan(stop_event, start_btn, stop_btn, status_label):
    stop_event.set()
    start_btn["state"] = "normal"
    stop_btn["state"] = "disabled"
    status_label.config(text="Stopping...")

# ---------- Build GUI ----------

def build_gui():
    root = tk.Tk()
    root.title("Simple Network Scanner")
    root.geometry("760x500")
    root.resizable(False, False)

    pad = {"padx": 8, "pady": 6}

    top = ttk.Frame(root, padding=10)
    top.pack(fill="x")

    ttk.Label(top, text="Target (URL / Hostname / IP):").grid(row=0, column=0, sticky="w", **pad)
    host_entry = ttk.Entry(top, width=45)
    host_entry.grid(row=0, column=1, **pad)
    host_entry.insert(0, "example.com")

    ttk.Label(top, text="Protocol:").grid(row=1, column=0, sticky="w", **pad)
    proto_choice = ttk.Combobox(top, values=["TCP", "UDP", "Both"], state="readonly", width=10)
    proto_choice.set("Both")
    proto_choice.grid(row=1, column=1, sticky="w", **pad)

    ttk.Label(top, text="Port range (e.g. 1-1024 or 22,80,443):").grid(row=2, column=0, sticky="w", **pad)
    ports_entry = ttk.Entry(top, width=45)
    ports_entry.grid(row=2, column=1, **pad)
    ports_entry.insert(0, "1-1024")

    # Controls
    control_frame = ttk.Frame(top)
    control_frame.grid(row=3, column=0, columnspan=2, sticky="w", **pad)

    tree = ttk.Treeview(root, columns=("Port", "Service", "Protocol", "Status"), show="headings", height=16)
    tree.heading("Port", text="Port")
    tree.heading("Service", text="Service")
    tree.heading("Protocol", text="Protocol")
    tree.heading("Status", text="Status")
    tree.column("Port", width=70, anchor="center")
    tree.column("Service", width=200, anchor="w")
    tree.column("Protocol", width=80, anchor="center")
    tree.column("Status", width=120, anchor="center")
    tree.pack(padx=10, pady=(6, 0), fill="both", expand=False)

    progress = ttk.Progressbar(root, orient="horizontal", length=700, mode="determinate")
    progress.pack(pady=8)

    status_label = ttk.Label(root, text="Idle")
    status_label.pack(pady=(0, 8))

    stop_event = threading.Event()

    start_btn = ttk.Button(control_frame, text="Start Scan",
                           command=lambda: start_scan(host_entry, proto_choice, ports_entry, tree, progress, status_label, start_btn, stop_btn, stop_event))
    start_btn.grid(row=0, column=0, **pad)

    stop_btn = ttk.Button(control_frame, text="Stop Scan",
                          command=lambda: stop_scan(stop_event, start_btn, stop_btn, status_label),
                          state="disabled")
    stop_btn.grid(row=0, column=1, **pad)

    # Right-click menu to clear results
    menu = tk.Menu(root, tearoff=0)
    menu.add_command(label="Clear results", command=lambda: [tree.delete(i) for i in tree.get_children()])

    def on_right_click(event):
        menu.post(event.x_root, event.y_root)

    tree.bind("<Button-3>", on_right_click)

    return root


if __name__ == "__main__":
    app = build_gui()
    app.mainloop()

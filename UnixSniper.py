import time
import socket
import struct
import statistics
import ctypes
import threading
import queue
import tkinter as tk
from tkinter import ttk
from pynput.mouse import Controller

SendInput = ctypes.windll.user32.SendInput

INPUT_MOUSE = 0
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004

class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", ctypes.c_long),
        ("dy", ctypes.c_long),
        ("mouseData", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ctypes.c_void_p),
    ]

class INPUT(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("mi", MOUSEINPUT)]
    _anonymous_ = ("u",)
    _fields_ = [("type", ctypes.c_ulong), ("u", _U)]

def send_click():
    down = INPUT(type=INPUT_MOUSE, mi=MOUSEINPUT(0, 0, 0, MOUSEEVENTF_LEFTDOWN, 0, 0))
    up   = INPUT(type=INPUT_MOUSE, mi=MOUSEINPUT(0, 0, 0, MOUSEEVENTF_LEFTUP,   0, 0))
    SendInput(1, ctypes.byref(down), ctypes.sizeof(INPUT))
    SendInput(1, ctypes.byref(up),   ctypes.sizeof(INPUT))

# NTP sync

def ntp_single_request(host: str, timeout: float = 0.6):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
            c.settimeout(timeout)

            pkt = b"\x1b" + (47 * b"\0")

            t1 = time.time()
            c.sendto(pkt, (host, 123))
            data, _ = c.recvfrom(1024)
            t4 = time.time()

            if len(data) < 48:
                return None

            u = struct.unpack("!12I", data[:48])

            tx_seconds = u[10]
            tx_fraction = u[11]

            t3 = (tx_seconds + (tx_fraction / 2**32)) - 2208988800

            return t3 - ((t1 + t4) / 2)
    except:
        return None

def ntp_offset(host="time.cloudflare.com", samples=5):
    vals = []
    for _ in range(samples):
        v = ntp_single_request(host)
        if v is not None:
            vals.append(v)
        time.sleep(0.05)
    if not vals:
        return None
    return statistics.median(vals)

# Timed macro thread

class TimedMacro(threading.Thread):
    def __init__(self, logger, unix_entry, offset_entry):
        super().__init__(daemon=True)
        self.logger = logger
        self.unix_entry = unix_entry
        self.offset_entry = offset_entry

        self.active_event = threading.Event()
        self.stop_event = threading.Event()
        self.mouse = Controller()

    def set_active(self, on: bool):
        if on:
            self.active_event.set()
            self.logger("[TimedMacro] Online")
        else:
            self.active_event.clear()
            self.logger("[TimedMacro] Offline (canceled)")

    def toggle(self):
        self.set_active(not self.active_event.is_set())

    def run(self):
        while not self.stop_event.is_set():
            if not self.active_event.wait(timeout=0.1):
                continue

            try:
                target_unix = int(self.unix_entry.get().strip())
                offset_ms_str = self.offset_entry.get().strip() or "100"
                offset = float(offset_ms_str) / 1000.0
            except:
                self.logger("Invalid input (UNIX / Offset)")
                self.active_event.clear()
                continue

            self.logger("Syncing NTP...")
            off = ntp_offset()
            if off is None:
                self.logger("NTP failed")
                self.active_event.clear()
                continue

            real_now = time.time() + off
            remaining = (target_unix - real_now) - offset

            if remaining <= 0:
                self.logger("Target already passed")
                self.active_event.clear()
                continue

            mono_target = time.monotonic() + remaining
            last_shown = None

            while self.active_event.is_set() and not self.stop_event.is_set():
                diff = mono_target - time.monotonic()
                if diff <= 0:
                    break

                sec = int(diff)
                if sec != last_shown:
                    self.logger(f"{sec}s")
                    last_shown = sec

                time.sleep(0.03)

            if not self.active_event.is_set() or self.stop_event.is_set():
                continue

            try:
                self.mouse.move(1, 0)
                self.mouse.move(-1, 0)
            except:
                pass

            time.sleep(0.001)
            send_click()
            self.logger("[TimedMacro] Click executed (NTP)")

            self.active_event.clear()

# GUI

class App:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("TimedBot —— (github.com/devLMX)")
        self.root.geometry("450x520")
        self.root.resizable(False, False)

        self.queue = queue.Queue()

        tk.Label(self.root, text="TimedBot", font=("Segoe UI", 14, "bold")).pack(pady=10)

        self.log_box = tk.Text(self.root, height=12, width=55)
        self.log_box.pack()

        tk.Label(self.root, text="UNIX Timestamp").pack(pady=(10, 0))
        self.unix_entry = tk.Entry(self.root, width=30)
        self.unix_entry.pack()

        tk.Label(self.root, text="Offset (ms)").pack(pady=(10, 0))
        self.offset_entry = tk.Entry(self.root, width=30)
        self.offset_entry.insert(0, "155")
        self.offset_entry.pack()

        self.timed_macro = TimedMacro(self.log, self.unix_entry, self.offset_entry)
        self.timed_macro.start()

        ttk.Button(self.root, text="Run", command=self.timed_macro.toggle).pack(pady=5)
        ttk.Button(self.root, text="Stop", command=lambda: self.timed_macro.set_active(False)).pack(pady=5)

        self.root.after(50, self.process_log)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    def log(self, msg: str):
        self.queue.put(msg)

    def process_log(self):
        while not self.queue.empty():
            self.log_box.insert(tk.END, self.queue.get() + "\n")
            self.log_box.see(tk.END)
        self.root.after(50, self.process_log)

    def on_close(self):
        try:
            self.timed_macro.set_active(False)
            self.timed_macro.stop_event.set()
        except:
            pass
        self.root.destroy()

if __name__ == "__main__":
    App()

import threading
import tkinter as tk
from tkinter import messagebox


def alert_user(file: str) -> None:
    def show_alert() -> None:
        root = tk.Tk()
        root.withdraw()
        messagebox.showwarning("Threat Detected", f"Suspicious file detected:\n{file}")
        root.destroy()

    threading.Thread(target=show_alert, daemon=True).start()
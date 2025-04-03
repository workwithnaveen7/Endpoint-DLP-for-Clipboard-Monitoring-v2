import time
import pyperclip
import json
import platform
import subprocess
import re
import tkinter as tk
from tkinter import messagebox

# Load Configuration
def load_config():
    try:
        with open("config.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {
            "sensitivity_level": "strict",
            "detect_email": True,
            "detect_phone_number": True,
            "detect_aadhaar": True,
            "detect_pan": True
        }

config = load_config()

# Multi-Platform Clipboard Clear
def clear_clipboard():
    os_name = platform.system()
    try:
        if os_name == "Windows":
            import win32clipboard
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.CloseClipboard()
        elif os_name == "Darwin":
            subprocess.run("pbcopy", text=True, input="")
        elif os_name == "Linux":
            subprocess.run("xclip -selection clipboard", shell=True, input="")
        pyperclip.copy("")  # Clear clipboard for all platforms
        print("Clipboard cleared.")
    except Exception as e:
        print(f"Error clearing clipboard: {e}")

# Sensitive Data Detection
def detect_sensitive_data(data):
    detected = []
    if config.get("detect_aadhaar", False) and detect_aadhaar(data):
        detected.append("Aadhaar Number")
    if config.get("detect_pan", False) and detect_pan(data):
        detected.append("PAN Number")
    if config.get("detect_phone_number", False) and detect_phone_number(data):
        detected.append("Phone Number")
    if config.get("detect_email", False) and detect_email(data):
        detected.append("Email Address")
    return detected

def detect_aadhaar(data):
    pattern = r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"
    return bool(re.search(pattern, data))

def detect_pan(data):
    pattern = r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"
    return bool(re.search(pattern, data))

def detect_phone_number(data):
    pattern = r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b"
    return bool(re.search(pattern, data))

def detect_email(data):
    pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    return bool(re.search(pattern, data))

# **Force User Response Before Pasting**
def ask_user_permission(detected_info):
    response = None

    def on_yes():
        nonlocal response
        response = True
        popup.destroy()

    def on_no():
        nonlocal response
        response = False
        popup.destroy()

    popup = tk.Tk()
    popup.title("Sensitive Data Alert")
    popup.geometry("400x250")  # Popup size
    popup.resizable(False, False)

    label = tk.Label(popup, text="Your clipboard contains:\n\n" + "\n".join(detected_info) + "\n\nAllow pasting?", wraplength=350)
    label.pack(pady=10)

    yes_button = tk.Button(popup, text="Yes", command=on_yes, width=10, bg="green", fg="white")
    yes_button.pack(side=tk.LEFT, padx=40, pady=10)

    no_button = tk.Button(popup, text="No", command=on_no, width=10, bg="red", fg="white")
    no_button.pack(side=tk.RIGHT, padx=40, pady=10)

    popup.attributes('-topmost', True)  # Force popup on top
    popup.protocol("WM_DELETE_WINDOW", lambda: None)  # Disable close button
    popup.mainloop()

    return response  # True if Yes, False if No

# **Monitor Clipboard Before Pasting**
def monitor_clipboard():
    print("Monitoring clipboard for pasting events...")

    previous_data = ""
    while True:
        try:
            current_data = pyperclip.paste()

            if current_data and current_data != previous_data:
                detected_info = detect_sensitive_data(current_data)

                if detected_info:
                    user_choice = ask_user_permission(detected_info)

                    if not user_choice:  # If user chooses "No"
                        clear_clipboard()
                        print("Sensitive data removed from clipboard.")
                    else:
                        print("User allowed pasting sensitive data.")

                previous_data = pyperclip.paste()  # Update last checked data

        except Exception as e:
            print(f"Error: {e}")

        time.sleep(1)

if __name__ == "__main__":
    monitor_clipboard()

import time
import pyperclip
import json
import platform
import subprocess
import re
import tkinter as tk
from tkinter import messagebox
import requests
import win32clipboard


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

#multi-Platform Clipboard Clear
def clear_clipboard():
    os_name = platform.system()
    try:
        if os_name == "Windows":
            
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.CloseClipboard()
        elif os_name == "Darwin":
            subprocess.run("pbcopy", text=True, input="")
        elif os_name == "Linux":
            subprocess.run("xclip -selection clipboard", shell=True, input="")
        pyperclip.copy("")  
        print("Clipboard cleared.")
    except Exception as e:
        print(f"Error clearing clipboard: {e}")

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

def get_highlight_patterns():
    patterns = []
    if config.get("detect_aadhaar", False):
        patterns.append(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")
    if config.get("detect_pan", False):
        patterns.append(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
    if config.get("detect_phone_number", False):
        patterns.append(r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b")
    if config.get("detect_email", False):
        patterns.append(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    return patterns


def ask_user_permission(detected_info, original_text):
    popup = tk.Tk()
    popup.title("Sensitive Data Alert")
    popup.geometry("500x400")
    popup.resizable(False, False)

    label = tk.Label(popup, text="Sensitive data detected. Click on red text to mask it or edit manually.\n", fg="black")
    label.pack()

    text_widget = tk.Text(popup, wrap=tk.WORD, height=15, width=60)
    text_widget.insert(tk.END, original_text)
    text_widget.pack(pady=10)

    # Highlight sensitive data and bind click to mask
    def mask_sensitive(event):
        index = text_widget.index(f"@{event.x},{event.y}")
        ranges = text_widget.tag_ranges("highlight")
        for i in range(0, len(ranges), 2):
            start, end = ranges[i], ranges[i + 1]
            if text_widget.compare(start, "<=", index) and text_widget.compare(index, "<=", end):
                value = text_widget.get(start, end)
                masked = mask_value(value)
                text_widget.delete(start, end)
                text_widget.insert(start, masked)
                text_widget.tag_remove("highlight", start, end)
                break

    text_widget.tag_config("highlight", foreground="red", font=("Arial", 10, "bold"))
    text_widget.bind("<Button-1>", mask_sensitive)

    # Add highlight tags
    for pattern in get_highlight_patterns():
        for match in re.finditer(pattern, original_text):
            start = f"1.0 + {match.start()} chars"
            end = f"1.0 + {match.end()} chars"
            text_widget.tag_add("highlight", start, end)

    def mask_value(value):
        value = value.strip()
        if re.fullmatch(r"\d{4}[-\s]?\d{4}[-\s]?\d{4}", value):  # Aadhaar
            return re.sub(r"\d{4}[-\s]?\d{4}", "XXXX-XXXX", value)
        elif re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", value):  # PAN
            return "XXXXX" + value[5:9] + value[9]
        elif re.fullmatch(r"(?:\+91[-\s]?)?[6-9]\d{9}", value):  # Phone
            return re.sub(r"\d{5}", "XXXXX", value, 1)
        elif re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value):  # Email
            parts = value.split("@")
            return "x" * len(parts[0]) + "@" + parts[1]
        else:
            return "REDACTED"

    def on_yes():
        cleaned_text = text_widget.get("1.0", tk.END).strip()
        pyperclip.copy(cleaned_text)
        popup.destroy()
        return True

    def on_no():
        clear_clipboard()
        popup.destroy()
        return False

    yes_button = tk.Button(popup, text="Yes", command=on_yes, width=10, bg="green", fg="white")
    yes_button.pack(side=tk.LEFT, padx=40, pady=10)

    no_button = tk.Button(popup, text="No", command=on_no, width=10, bg="red", fg="white")
    no_button.pack(side=tk.RIGHT, padx=40, pady=10)

    popup.attributes('-topmost', True)
    popup.protocol("WM_DELETE_WINDOW", lambda: None)
    popup.mainloop()

    return True

def detect_urls(text):
    url_pattern = r"https?://[^\s]+"
    return re.findall(url_pattern, text)

def is_phishing_link(url):
    try:
        response = requests.get(f"https://phishtank.com/checkurl/{url}", timeout=5)
        return "phish" in response.text.lower()
    except requests.RequestException as e:
        print(f"Error checking PhishTank: {e}")
        return False
    
def alert_phishing(url):
    popup = tk.Tk()
    popup.title("Phishing Alert")
    popup.geometry("500x200")
    popup.resizable(False, False)

    label = tk.Label(
        popup,
        text=f"⚠️ WARNING: The copied URL is a known phishing link!\n\n{url}\n\nClipboard will be cleared.",
        fg="red",
        font=("Arial", 12, "bold"),
        wraplength=480
    )
    label.pack(pady=10)

    ok_button = tk.Button(popup, text="OK", command=popup.destroy, width=10, bg="red", fg="white")
    ok_button.pack(pady=10)

    popup.attributes('-topmost', True)
    popup.protocol("WM_DELETE_WINDOW", lambda: None)
    popup.mainloop()





def monitor_clipboard():
    print("Monitoring clipboard...")

    previous_data = ""
    while True:
        try:
            current_data = pyperclip.paste()

            if current_data and current_data != previous_data:
                
                # ✅detect phishing url
                urls = detect_urls(current_data)
                for url in urls:
                    if is_phishing_link(url):
                        clear_clipboard()
                        alert_phishing(url)
                        print(f"⚠️ Phishing link detected and removed: {url}")
                        continue  

                # ✅ detect sensitive data
                detected_info = detect_sensitive_data(current_data)
                if detected_info:
                    user_choice = ask_user_permission(detected_info, current_data)

                    if not user_choice:  
                        clear_clipboard()
                        print("Sensitive data removed from clipboard.")
                    else:
                        print("User allowed sensitive data.")

                previous_data = pyperclip.paste()

        except Exception as e:
            print(f"Error: {e}")

        time.sleep(1)

if __name__ == "__main__":
    monitor_clipboard()

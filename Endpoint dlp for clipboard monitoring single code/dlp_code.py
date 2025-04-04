import time
import pyperclip
import json
import platform
import subprocess
import re
import tkinter as tk
from tkinter import messagebox, ttk
import requests
import win32clipboard
import threading


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
        patterns.append((r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", "Aadhaar"))
    if config.get("detect_pan", False):
        patterns.append((r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", "PAN"))
    if config.get("detect_phone_number", False):
        patterns.append((r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b", "Phone"))
    if config.get("detect_email", False):
        patterns.append((r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email"))
    return patterns


def create_futuristic_button(parent, text, command, bg_color="#1E90FF", hover_color="#0066CC"):
    btn = tk.Button(
        parent,
        text=text,
        command=command,
        bg=bg_color,
        fg="white",
        font=("Segoe UI", 10, "bold"),
        relief=tk.FLAT,
        borderwidth=0,
        padx=15,
        pady=8,
        cursor="hand2"
    )

    # Hover effect
    def on_enter(e):
        btn['background'] = hover_color

    def on_leave(e):
        btn['background'] = bg_color

    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)

    return btn


def ask_user_permission(detected_info, original_text):
    # Create a themed popup with dark mode
    popup = tk.Tk()
    popup.title("Data Protection Alert")
    popup.geometry("550x450")
    popup.configure(bg="#1F2937")
    popup.resizable(True, True)  # Allow resizing for responsiveness
    popup.overrideredirect(True)

    # Set minimum size
    popup.minsize(450, 400)

    # Enable glass effect on Windows if possible
    try:
        from ctypes import windll
        popup.attributes("-alpha", 0.95)  # Slight transparency
    except:
        pass

    # Create a frame for the header
    header_frame = tk.Frame(popup, bg="#111827", pady=10)
    header_frame.pack(fill=tk.X)

    # Add alert icon and title
    alert_label = tk.Label(
        header_frame,
        text="⚠️ SENSITIVE DATA DETECTED",
        font=("Segoe UI", 14, "bold"),
        fg="#FFA500",
        bg="#111827"
    )
    alert_label.pack()

    # Add description
    description = tk.Label(
        popup,
        text="Click on highlighted text to mask it or edit manually before proceeding.",
        font=("Segoe UI", 10),
        fg="#E5E7EB",
        bg="#1F2937",
        wraplength=500
    )
    description.pack(pady=(10, 5))

    # Add detected types
    types_text = ", ".join(detected_info)
    types_label = tk.Label(
        popup,
        text=f"Detected: {types_text}",
        font=("Segoe UI", 9),
        fg="#F87171",
        bg="#1F2937"
    )
    types_label.pack(pady=(0, 10))

    # Create a frame for the text area with a border
    text_frame = tk.Frame(popup, bg="#374151", padx=2, pady=2)
    text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

    # Text widget with dark theme
    text_widget = tk.Text(
        text_frame,
        wrap=tk.WORD,
        height=12,
        width=55,
        font=("Consolas", 10),
        bg="#374151",
        fg="#F9FAFB",
        insertbackground="white",
        selectbackground="#3B82F6",
        relief=tk.FLAT
    )
    text_widget.insert(tk.END, original_text)
    text_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # Add scrollbar
    scrollbar = ttk.Scrollbar(text_widget, orient="vertical", command=text_widget.yview)
    text_widget.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

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
                flash_success(popup)
                break

    def animate_highlight():
        colors = ["#FF5252", "#FF7676", "#FF9C9C", "#FF7676", "#FF5252"]
        i = 0
        while True:
            try:
                if not popup.winfo_exists():
                    break
                text_widget.tag_config("highlight", foreground=colors[i % len(colors)], background="#3B0B0B")
                i += 1
                time.sleep(0.5)
                popup.update_idletasks()
            except tk.TclError:
                break


    animation_thread = threading.Thread(target=animate_highlight, daemon=True)
    animation_thread.start()

    text_widget.tag_config("highlight", foreground="#FF5252", background="#3B0B0B", font=("Consolas", 10, "bold"))
    text_widget.bind("<Button-1>", mask_sensitive)

    for pattern, tag_type in get_highlight_patterns():
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

    def flash_success(window):
        original_bg = window.cget("bg")
        for _ in range(2):
            window.configure(bg="#1da1f2")
            window.update_idletasks()
            time.sleep(0.1)
            window.configure(bg=original_bg)
            window.update_idletasks()
            time.sleep(0.1)

    def on_yes():
        cleaned_text = text_widget.get("1.0", tk.END).strip()
        pyperclip.copy(cleaned_text)
        show_success_notification("Data safely processed")
        popup.destroy()
        return True

    def on_no():
        clear_clipboard()
        show_success_notification("Clipboard cleared")
        popup.destroy()
        return False

    btn_frame = tk.Frame(popup, bg="#1F2937", pady=15)
    btn_frame.pack(fill=tk.X)

    yes_btn = create_futuristic_button(btn_frame, "PROCEED", on_yes, bg_color="#10B981", hover_color="#059669")
    yes_btn.pack(side=tk.LEFT, padx=40)

    no_btn = create_futuristic_button(btn_frame, "DISCARD", on_no, bg_color="#EF4444", hover_color="#B91C1C")
    no_btn.pack(side=tk.RIGHT, padx=40)

    status_bar = tk.Label(
        popup,
        text="Secure DLP Monitor Active",
        font=("Segoe UI", 8),
        fg="#9CA3AF",
        bg="#111827",
        bd=1,
        relief=tk.FLAT
    )
    status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    popup.attributes('-topmost', True)
    popup.protocol("WM_DELETE_WINDOW", lambda: None)

    popup.update_idletasks()
    width = popup.winfo_width()
    height = popup.winfo_height()
    x = (popup.winfo_screenwidth() // 2) - (width // 2)
    y = (popup.winfo_screenheight() // 2) - (height // 2)
    popup.geometry(f'+{x}+{y}')

    popup.attributes('-alpha', 0.0)
    for i in range(0, 10):
        popup.attributes('-alpha', i / 10)
        popup.update()
        time.sleep(0.02)

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


def show_success_notification(message):
    """Shows a small temporary notification"""
    notification = tk.Tk()
    notification.withdraw()
    notification.attributes("-alpha", 0.9)
    notification.attributes("-topmost", True)
    notification.overrideredirect(True)

    frame = tk.Frame(notification, bg="#111827", padx=20, pady=10)
    frame.pack(fill=tk.BOTH, expand=True)

    label = tk.Label(
        frame,
        text=message,
        fg="#10B981",
        bg="#111827",
        font=("Segoe UI", 10, "bold"),
    )
    label.pack(padx=10, pady=10)

    screen_width = notification.winfo_screenwidth()
    screen_height = notification.winfo_screenheight()
    notification.geometry(f"300x80+{screen_width - 320}+{screen_height - 120}")

    notification.deiconify()

    for i in range(0, 11):
        notification.attributes("-alpha", i / 10)
        notification.update()
        time.sleep(0.02)

    notification.after(2000, lambda: notification.destroy())


def alert_phishing(url):
    popup = tk.Tk()
    popup.title("SECURITY THREAT DETECTED")
    popup.geometry("550x300")
    popup.configure(bg="#1F1F1F")
    popup.resizable(False, False)

    def pulse_border(index=0):
        colors = ["#FF0000", "#CC0000", "#990000", "#CC0000"]
        popup.configure(highlightbackground=colors[index % len(colors)], highlightthickness=3)
        popup.after(300, pulse_border, (index + 1) % len(colors))


    popup.configure(highlightbackground="#FF0000", highlightthickness=3)
    pulse_border()

    warning_frame = tk.Frame(popup, bg="#1F1F1F", pady=10)
    warning_frame.pack(fill=tk.X)

    warning_label = tk.Label(
        warning_frame,
        text="⚠️ CRITICAL SECURITY ALERT ⚠️",
        fg="#FF0000",
        bg="#1F1F1F",
        font=("Impact", 16, "bold")
    )
    warning_label.pack()

    description_frame = tk.Frame(popup, bg="#1F1F1F", padx=20)
    description_frame.pack(fill=tk.BOTH, expand=True)

    description = tk.Label(
        description_frame,
        text="A malicious phishing link has been detected and blocked!",
        fg="#FFFFFF",
        bg="#1F1F1F",
        font=("Segoe UI", 12),
        wraplength=480
    )
    description.pack(pady=(10, 5))

    url_frame = tk.Frame(description_frame, bg="#2D2D2D", bd=1, relief=tk.SUNKEN, padx=10, pady=10)
    url_frame.pack(fill=tk.X, pady=10)

    url_label = tk.Label(
        url_frame,
        text=url,
        fg="#FF9999",
        bg="#2D2D2D",
        font=("Consolas", 10),
        wraplength=480
    )
    url_label.pack()

    info_label = tk.Label(
        description_frame,
        text="This URL has been identified as a phishing attempt.\nYour clipboard has been cleared for security.",
        fg="#CCCCCC",
        bg="#1F1F1F",
        font=("Segoe UI", 10),
        justify=tk.LEFT
    )
    info_label.pack(pady=10, anchor=tk.W)

    ok_button = create_futuristic_button(
        popup,
        "ACKNOWLEDGE",
        popup.destroy,
        bg_color="#FF3333",
        hover_color="#CC0000"
    )
    ok_button.pack(pady=20)

    popup.attributes('-alpha', 0.0)
    popup.attributes('-topmost', True)
    popup.protocol("WM_DELETE_WINDOW", lambda: None)

    popup.update_idletasks()
    width = popup.winfo_width()
    height = popup.winfo_height()
    x = (popup.winfo_screenwidth() // 2) - (width // 2)
    y = (popup.winfo_screenheight() // 2) - (height // 2)
    popup.geometry(f'+{x}+{y}')

    for i in range(0, 10):
        popup.attributes('-alpha', i / 10)
        popup.update()
        time.sleep(0.03)

    popup.mainloop()

import io
import PyPDF2
from PIL import ImageGrab, Image
import pytesseract
import os

def scan_clipboard_pdf():
    """
    Detects and scans PDF files that have been copied to the clipboard.
    Extracts text from the PDF and checks for sensitive information.
    """
    try:
        # Check if PDF file is in clipboard
        pdf_data = None
        
        # Method 1: Try to get PDF directly from clipboard (Windows)
        try:
            import win32clipboard
            win32clipboard.OpenClipboard()
            if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_HDROP):
                file_paths = win32clipboard.GetClipboardData(win32clipboard.CF_HDROP)
                for file_path in file_paths:
                    if file_path.lower().endswith('.pdf'):
                        with open(file_path, 'rb') as f:
                            pdf_data = f.read()
                        break
            win32clipboard.CloseClipboard()
        except Exception as e:
            print(f"Error accessing clipboard files: {e}")
        
        # Method 2: Try to get from image clipboard (screenshot of PDF)
        if pdf_data is None:
            try:
                img = ImageGrab.grabclipboard()
                if img:
                    # Convert image to text using OCR
                    text = pytesseract.image_to_string(img)
                    if text:
                        # Check extracted text for sensitive information
                        detected_info = detect_sensitive_data(text)
                        if detected_info:
                            return text, detected_info
            except Exception as e:
                print(f"Error processing clipboard image: {e}")
        
        # Method 3: Process actual PDF data
        if pdf_data:
            extracted_text = extract_text_from_pdf(pdf_data)
            detected_info = detect_sensitive_data(extracted_text)
            if detected_info:
                return extracted_text, detected_info
            
        return None, None
        
    except Exception as e:
        print(f"Error scanning clipboard PDF: {e}")
        return None, None

def extract_text_from_pdf(pdf_data):
    """
    Extracts text from PDF data using PyPDF2.
    
    Args:
        pdf_data: Binary PDF data
        
    Returns:
        str: Extracted text from the PDF
    """
    text = ""
    
    # Using PyPDF2
    try:
        pdf_file = io.BytesIO(pdf_data)
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        for page_num in range(len(pdf_reader.pages)):
            page_text = pdf_reader.pages[page_num].extract_text()
            if page_text:
                text += page_text + "\n"
    except Exception as e:
        print(f"PyPDF2 extraction error: {e}")
    
    # If we have no text and have poppler/pdftotext installed, try that as a fallback
    if not text.strip():
        try:
            # Create a temporary file
            temp_pdf_path = "temp_clipboard.pdf"
            with open(temp_pdf_path, "wb") as f:
                f.write(pdf_data)
            
            # Use pdftotext if available
            import subprocess
            result = subprocess.run(
                ["pdftotext", temp_pdf_path, "-"],
                capture_output=True,
                text=True,
                check=True
            )
            text = result.stdout
            
            # Clean up
            if os.path.exists(temp_pdf_path):
                os.remove(temp_pdf_path)
                
        except Exception as e:
            print(f"pdftotext extraction error: {e}")
            # Clean up if file exists
            if os.path.exists("temp_clipboard.pdf"):
                try:
                    os.remove("temp_clipboard.pdf")
                except:
                    pass
    
    return text

def handle_pdf_clipboard():
    """
    Main function to handle PDFs in clipboard.
    """
    pdf_text, detected_info = scan_clipboard_pdf()
    
    if pdf_text and detected_info:
        # Use the existing UI for handling sensitive information
        user_choice = ask_user_permission(detected_info, pdf_text)
        
        if not user_choice:
            clear_clipboard()
            print("Sensitive data removed from clipboard.")
            show_success_notification("PDF data cleared - sensitive information detected")
        else:
            print("User allowed sensitive data from PDF.")
            show_success_notification("PDF data processed with user approval")
    
    return pdf_text is not None


def monitor_clipboard():
    print("Monitoring clipboard...")
    show_success_notification("DLP Monitor Activated")

    previous_data = ""
    while True:
        try:
            current_data = pyperclip.paste()

            if current_data and current_data != previous_data:
                # First check if there's a PDF in clipboard
                pdf_handled = handle_pdf_clipboard()
                
                if not pdf_handled:
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

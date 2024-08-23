import re
import math
import tkinter as tk
from tkinter import messagebox

# Load the common passwords list
def load_common_passwords():
    try:
        with open('common_passwords.txt', 'r') as file:
            common_passwords = {line.strip() for line in file}
        return common_passwords
    except FileNotFoundError:
        return set()

# Entropy calculation
def calculate_entropy(password):
    charset_size = 0
    if re.search(r"[a-z]", password):  # Lowercase letters
        charset_size += 26
    if re.search(r"[A-Z]", password):  # Uppercase letters
        charset_size += 26
    if re.search(r"\d", password):  # Digits
        charset_size += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # Special characters
        charset_size += len(r"!@#$%^&*(),.?\":{}|<>")
    
    if charset_size == 0:
        return 0
    
    entropy = len(password) * math.log2(charset_size)
    return entropy

# Password strength checker
def check_password_strength(password):
    score = 0

    # Length check
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1

    # Character variety check
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1

    # Check for common patterns
    common_patterns = ["1234", "password", "admin", "qwerty", "abc123"]
    if any(pattern in password.lower() for pattern in common_patterns):
        score -= 2  # Penalize heavily for common patterns

    # Check against common passwords
    common_passwords = load_common_passwords()
    if password.lower() in common_passwords:
        return "Very Weak (Common Password)"

    # Entropy calculation
    entropy = calculate_entropy(password)
    if entropy < 28:
        strength = "Very Weak"
    elif entropy < 36:
        strength = "Weak"
    elif entropy < 60:
        strength = "Moderate"
    else:
        strength = "Strong"
    
    return strength

# GUI for Password Strength Checker
def check_strength():
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password.")
        return
    
    strength = check_password_strength(password)
    messagebox.showinfo("Password Strength", f"Password strength: {strength}")

# Setup GUI
root = tk.Tk()
root.title("Password Strength Checker")

# Label and entry for password
password_label = tk.Label(root, text="Enter Password:")
password_label.pack(pady=5)

password_entry = tk.Entry(root, width=40, show='*')
password_entry.pack(pady=5)

# Button to check password strength
check_button = tk.Button(root, text="Check Strength", command=check_strength)
check_button.pack(pady=20)

root.mainloop()

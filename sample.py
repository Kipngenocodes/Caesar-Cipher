'''
This Python program focuses on checking the password strength entered by the user.
It also refers to an English dictionary and flags common words.
'''

import re
import hashlib
import requests
import math
import tkinter as tk
from tkinter import messagebox, ttk

def loading_English_dictionary_words():
    try:
        # Opens the english_dictionary.txt in read mode
        with open('english_dictionary.txt', 'r') as file:
            # Read each line of the file, remove any surrounding whitespace,
            # and convert the text into lowercase
            english_words = {line.strip().lower() for line in file}
        # Returns the set of English words
        return english_words
    except FileNotFoundError:
        # An empty set is returned if the file is not available
        return set()

# Checking if the password contains a dictionary word in refernce to dictionary provide
def checking_dictionary_word(password, english_words):
    # Normalizes the password to lowercase
    password_lowercase = password.lower()
    # Checks the whole password
    if password_lowercase in english_words:
        return True
    # Checking all substrings of the password
    for i in range(len(password_lowercase)):
        # Iterates over all possible substrings starting at index i
        for j in range(i + 1, len(password_lowercase) + 1):
            # Checks if any substring of the password is a dictionary word
            if password_lowercase[i:j] in english_words:
                return True
    # If no dictionary word is found, returns False
    return False

# Loading common passwords
def loading_common_passwords():
    try:
        # Opens the common_password.txt in read mode
        with open('common_password.txt', 'r') as file:
            # Read each line of the file, remove any surrounding whitespace
            common_password = {line.strip() for line in file}
        # Returns the set of common passwords    
        return common_password
    except FileNotFoundError:
        # An empty set is returned if the file is not available
        return set()

# The goal here is to check if the password has been involved in a data breach
def check_pwned_password(password):  # sourcery skip: use-next
    # Hashes the password using SHA-1 and converts the result to uppercase
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # Splits the hash into the first five characters and the remainder
    first5, tail = sha1_password[:5], sha1_password[5:]
    # Constructs the URL to query the HIBP API with the first 5 characters of the hash
    url = f"https://api.pwnedpasswords.com/range/{first5}"
    try:
        # Sends an HTTP GET request to the API with the URL
        response = requests.get(url)
        # Splits the response into individual hash suffixes and their associated breach counts
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            # If the hash tail matches, return the count of breaches
            if h == tail:
                return int(count)
        # If no match is found, return 0
        return 0
    except requests.RequestException:
        return -1  # Indicate API error

# Calculating the entropy
def calculate_entropy(password):
    charset_size = 0
    
    # Check and count the variety of characters in the password
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"[0-9]", password):
        charset_size += 10
    if re.search(r"[!@#$%^&*()_+=-{};:'<>]", password):
        charset_size += 32
    if re.search(r"\s", password):
        charset_size += 1 
    
    # If no valid characters are found, return 0 entropy
    if charset_size == 0:
        return 0
    
    # Calculate entropy based on the length of the password and character set size
    entropy = len(password) * math.log2(charset_size)
    return entropy

# Checking for sequential patterns
def check_sequential_pattern(password):
    sequences = [
        'abcdefghijklmnopqrstuvwxyz',
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        '0123456789',
        'qwertyuiop',
        'asdfghjkl',
        'zxcvbnm'
    ]
    
    # Check if the password contains any common sequential patterns
    for sequence in sequences:
        for i in range(len(sequence) - 2):
            sub_seq = sequence[i:i + 3]
            if sub_seq in password.lower():
                return True
    return False

# Checking for repeated characters
def check_repeated_characters(password):
    # Returns True if the password contains three or more consecutive identical characters
    return re.search(r'(.)\1\1', password) is not None

# Provide suggestions for improving the password
def provide_suggestions(password):
    suggestions = []
    
    # Add suggestions based on password length and character variety
    if len(password) < 12:
        suggestions.append("Password should be at least 12 characters long")
    if not re.search(r"[a-z]", password):
        suggestions.append("Add lowercase letters.")
    if not re.search(r"[A-Z]", password):
        suggestions.append("Add uppercase letters.")
    if not re.search(r"\d", password):
        suggestions.append("Add digits.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        suggestions.append("Add special characters.")
    if check_sequential_pattern(password):
        suggestions.append("Avoid sequential keyboard patterns.")
    if check_repeated_characters(password):
        suggestions.append("Avoid repeated characters.")
    
    return suggestions

# Main password evaluation function
def evaluate_password(password, english_words):
    # Load the common passwords
    common_password = loading_common_passwords()
    
    # Check if the password is a common password
    if password.lower() in common_password:
        return {
            'strength': 'Very Weak',
            'color': 'red',
            'score': 0,
            'suggestions': ['This password is too common. Choose a more unique password.']
        }
    
    # Check if the password has been found in a data breach
    pwned_count = check_pwned_password(password)
    if pwned_count > 0:
        return {
            'strength': 'Compromised',
            'color': 'darkred',
            'score': 0,
            'suggestions': [f"This password has been found in data breaches {pwned_count} times. Choose a different password."]
        }
    elif pwned_count == -1:
        pwned_message = "Could not check against breached passwords. Check your internet connection."
    else:
        pwned_message = ""
    
    # Check if the password contains any dictionary words
    if checking_dictionary_word(password, english_words):
        return {
            'strength': 'Very Weak',
            'color': 'red',
            'score': 0,
            'suggestions': ['Your password contains dictionary words. Avoid using common words.']
        }
    
    # Calculate the entropy of the password
    entropy = calculate_entropy(password)
    
    # Determine the strength of the password based on entropy
    if entropy < 28:
        strength = "Very Weak"
        color = "red"
        score = 20
    elif entropy < 36:
        strength = 'Weak'
        color = 'orange'
        score = 40
    elif entropy < 60:
        strength = 'Moderate'
        color = 'yellow'
        score = 60
    elif entropy < 100:
        strength = 'Strong'
        color = 'lightgreen'
        score = 80
    else:
        strength = 'Very Strong'
        color = 'green'
        score = 100
    
    # Generate suggestions for improving the password
    suggestions = provide_suggestions(password)
    
    if pwned_message:
        suggestions.append(pwned_message)
    
    # Return the password evaluation results
    return {
        'strength': strength,
        'color': color,
        'score': score,
        'suggestions': suggestions
    }

# Creating and setting up Graphical User Interface (GUI)
def create_gui():
    # Load the dictionary words
    english_words = loading_English_dictionary_words()

    # Event handler for password entry
    def on_password_entry(event):
        password = password_entry.get()
        result = evaluate_password(password, english_words)
        strength_label.config(text=f"Strength: {result['strength']}", fg=result['color'])
        progress_bar['value'] = result['score']
        suggestions_text.delete(1.0, tk.END)
        if result['suggestions']:
            suggestions_text.insert(tk.END, "\n".join(result['suggestions']))
        else:
            suggestions_text.insert(tk.END, "Your password is strong.")

    # Copy password to clipboard
    def copy_to_clipboard():
        password = password_entry.get()
        if password:
            root.clipboard_clear()
            root.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showwarning("No Password", "No password to copy.")

    # Clear the input fields
    def clear_input():
        password_entry.delete(0, tk.END)
        strength_label.config(text="Strength: ", fg="black")
        progress_bar['value'] = 0
        suggestions_text.delete(1.0, tk.END)

    # Set up the main window
    root = tk.Tk()
    root.title("Enhanced Password Strength Checker")
    root.geometry("500x400")
    root.resizable(False, False)

    # Password Entry
    frame = tk.Frame(root, pady=10)
    frame.pack()
    password_label = tk.Label(frame, text="Enter Password:")
    password_label.pack(side=tk.LEFT)
    password_entry = tk.Entry(frame, width=30, show='*')
    password_entry.pack(side=tk.LEFT, padx=10)
    password_entry.bind("<KeyRelease>", on_password_entry)

    # Strength Label
    strength_label = tk.Label(root, text="Strength: ", font=('Helvetica', 12))
    strength_label.pack(pady=5)

    # Progress Bar
    progress_bar = ttk.Progressbar(root, length=300, mode='determinate')
    progress_bar.pack(pady=5)

    # Suggestions Text
    suggestions_label = tk.Label(root, text="Suggestions:", font=('Helvetica', 12))
    suggestions_label.pack(pady=5)
    suggestions_text = tk.Text(root, height=8, width=60)
    suggestions_text.pack(pady=5)

    # Buttons Frame
    buttons_frame = tk.Frame(root, pady=10)
    buttons_frame.pack()
    copy_button = tk.Button(buttons_frame, text="Copy Password", command=copy_to_clipboard)
    copy_button.pack(side=tk.LEFT, padx=5)
    clear_button = tk.Button(buttons_frame, text="Clear", command=clear_input)
    clear_button.pack(side=tk.LEFT, padx=5)
    exit_button = tk.Button(buttons_frame, text="Exit", command=root.quit)
    exit_button.pack(side=tk.LEFT, padx=5)

    root.mainloop()

if __name__ == "__main__":
    create_gui()

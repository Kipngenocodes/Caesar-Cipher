'''
This python program focuses on checkig the passowrd strength entered by the use. 
It also refer to english dictionary and flag common words 
'''

import re
import hashlib
import requests
import math


def loading_English_dictionary_words():
    try:
        # opens the english-dictionary.txt in read mode
        with open('english_dictionary.txt', 'r') as file:
            # read each line of the file, removes any surrounding whitespace,
            # and converts text into a lowercase
            english_words = {line.strip().lower() for line in file}
        # it return the set of english words 
        return english_words
    except FileNotFoundError:
        # empty set is returned if the file is not available. 
        return set()
    
# checking if password contains a dictinary word
def checking_dictionary_word(password, english_words):  # sourcery skip: use-any
    # checking and normalizing the passord are in lowercase
    password_lowercase= password.lower()
    # check the whole password
    if  password_lowercase in english_words:
        return True
    # checking for all substrings of the password.
    # Iterates over each character in the password.
    for i in range(len(password_lowercase)):
        # Iterates over all possible substrings starting at index i.
        for j in range(i+1, len(password)+1):
            # Checks if any substring of the password is a dictionary word.
            if password_lowercase[i:j] in english_words:
                return True 
         # if no dictionary word is found, returns False
        return False


# Loading common passowrds which are based on the keyboard layout
def loading_common_passwords():
    try:
        # opens the common_password.txt in read mode
        with open('common_password.txt', 'r') as file:
            # read each line of the file, removes any surrounding whitespace
            common_password = {line.strip() for line in file}
        # it return the set of common_passowrds    
        return common_password
    except FileNotFoundError:
        # empty set is returned if the file is not available.
        return set()

#  the goal here is to check if the password have got in databreach 
def check_pwned_password(password):  # sourcery skip: use-next
    # it hashes password using SHA-1 and converts results to upercase
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # split the first five hashes and last five to tail
    first5, tail = sha1_password[:5], sha1_password[5:]
    # Constructs the URL to query the HIBP API with the first 5 characters of the hash.
    url = f"https://api.pwnedpasswords.com/range/{first5}"
    try:
        # Sends an HTTP GET request to the API with the URL.
        response = requests.get(url)
        # Splits the response into individual hash suffixes and their associated breach counts.
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == tail:
                return int(count)
        return 0
    except requests.RequestException:
        return -1  # Indicate API error

    
# calculating the entropy 
def calculate_entropy(password):
    charset_size = 0
    
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"[0-9]", password):
        charset_size += 10
    if re.search(r"[!@#$%^&*()_+=-{};:'<>]", password):
        charset_size += 32
    if re.search(r"\d", password):
        charset_size += 10
    if re.search(r"\s", password):
        charset_size += 1 
    if charset_size == 0:
        return 0
    
    entropy = len(password)* math.log2(charset_size)
    return entropy

    
    
    pass
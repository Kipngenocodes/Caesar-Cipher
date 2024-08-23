''' 
The program highlight the Caesar Cipher. 
It shift each character fro range of 1 to 25 inclusive.
What it does:
- It takes a string as input from the user.
- It shifts each character in the string by a certain number of places down the alphabet.
- It prints out the encrypted string.
'''

def  caesar_cipher(text, shift):
    encrypted_text = ""
    
    for char in text:
        if char.isalpha():
            # Determine the base ASCII code ("a" or "A")
            base = ord('a') if char.islower() else ord('A')
            # Perform the shift
            shifted_char = chr((ord(char) - base + shift) % 26 + base)
            encrypted_text += shifted_char
        else:
            # Non-alphabetic characters are added as they are
            encrypted_text += char

    return encrypted_text

def get_valid_shift():
    while True:
        try:
            shift = int(input("Enter the shift value (1-25): "))
            if 1 <= shift <= 25:
                return shift
            else:
                print("The shift value must be between 1 and 25. Please try again.")
        except ValueError:
            print("Invalid input. Please enter an integer between 1 and 25.")

def main():
    text = input("Enter the text to encrypt: ")
    shift = get_valid_shift()
    encrypted_text = caesar_cipher(text, shift)
    print("Encrypted text:", encrypted_text)

# Run the program
main()

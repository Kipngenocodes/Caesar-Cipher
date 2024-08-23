'''
import of regular expression and
allow you to search and maipulate strings based on patterns
'''
import re


# creation of a fuction to handle password strength checking.
def check_password_sterngth(password):
    # initilaizing the password score
    password_score = 0
    
    # checking the password length
    if len(password) >= 8:
        password_score += 1
    
    if len(password) >= 12:
        password_score += 3
    
    # checking for the lowercase in password
    if re.search("[a-z]", password):
        password_score += 1
    
    # checking for the uppercase in password 
    if re.search("[A-Z]", password):
        password_score += 1
        
    # checking for digits in passowrd
    if re.search("[0-9]", password):
        password_score += 1
    
    # checking for special character in password
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        password_score += 1
        
    # determination of the strength based on password_score
    if password_score == 8:
        return 'Your password is very strong'
    
    elif password_score == 7:
        return 'Your password is strong'
    
    elif password_score == 6:
        return 'Your password is good'
    
    elif password_score ==5:
        return 'Your password is moderate'
    
    else:
        return 'Your password is weak. Action must be taken to improve it.'
    
def main():  # sourcery skip: remove-redundant-fstring
    # instructing a user to enter the passowrd of their choice
    password = input("Enter your password: ")
    
    # checking the password strength
    password_strength = check_password_sterngth(password)
    
    # displaying the results of the password. 
    print('The password strength is: ', password_strength)
    
# executing the program
if __name__ == "__main__":
    main()




# this file helps us work with passwords
# it helps us create passwords manually, or automatically and randomly
# also it helps us check if the password follows the strength policies or not
# all this is provided by some functions :)

# our passwords' strength policies are:
#   1. 16 minimum
#   2. contains at least one alphabet lowercase
#   3. contains at least one alphabet uppercase
#   4. contains at least one digit
#   5. contains at least one special character


from random import choice
from string import ascii_lowercase, ascii_uppercase, digits, punctuation
import bcrypt


# choose if the password is random or not
def pwd_random_or_not():
    while True:
        rand = input('Random password? yes or no? ')
        if rand.lower() in ['yes', 'no']:
            break
    return rand.lower() == 'yes'


# verify that the password follow strength policies
def is_pwd_strong(pwd):
    alpha_lower_exists = False
    alpha_upper_exists = False
    digit_exists = False
    special_char_exists = False
    i = -1
    while True:
        i += 1
        if pwd[i] in ascii_lowercase:
            alpha_lower_exists = True
        elif pwd[i] in ascii_uppercase:
            alpha_upper_exists = True
        elif pwd[i] in digits:
            digit_exists = True
        elif pwd[i] in punctuation:
            special_char_exists = True
        else:
            print("White Spaces are prohibited!")
            return False
        is_strong = alpha_lower_exists and alpha_upper_exists and digit_exists and special_char_exists
        if is_strong or i == len(pwd) - 1:
            break
    if is_strong:
        return True
    else:
        print('Password is very week. Try another one!')
        return False


def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed


def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)


def create_pwd_randomly():
    all_chars = ascii_lowercase + ascii_uppercase + digits + punctuation
    pwd = ''.join([choice(all_chars) for _ in range(16)])
    while not is_pwd_strong(pwd):
        pwd = ''.join([choice(all_chars) for _ in range(16)])
    print(f'Password = {pwd}')
    return pwd


# generate a password by the user himself
def create_pwd_manually():
    while True:
        respect_policies = input("Wanna u follow strength polices? yes or no(Y/n)?")
        dont_check_pwd = True
        if respect_policies.lower() in ["yes", "y"]:
            dont_check_pwd = False
        pwd = input('Password: ')
        if dont_check_pwd or is_pwd_strong(pwd):
            break
    return pwd

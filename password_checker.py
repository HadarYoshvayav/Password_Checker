import requests
import re
import hashlib

def check_password_strength(password):
    length_check = len(password) >= 8
    upper_check = any(char.isupper() for char in password)
    lower_check = any(char.islower() for char in password)
    digit_check = any(char.isdigit() for char in password)
    special_check = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

    suggestions = []
    if not length_check:
        suggestions.append("Make sure your password is at least 8 characters long.")
    if not upper_check:
        suggestions.append("Include at least one uppercase letter.")
    if not lower_check:
        suggestions.append("Include at least one lowercase letter.")
    if not digit_check:
        suggestions.append("Include at least one digit.")
    if not special_check:
        suggestions.append("Include at least one special character.")

    return {
        "strength": length_check and upper_check and lower_check and digit_check and special_check,
        "suggestions": suggestions
    }

def check_password_breach(password):
    hashed_password = hash_password(password)
    url = f"https://api.pwnedpasswords.com/range/{hashed_password[:5]}"
    response = requests.get(url)

    if response.status_code != 200:
        raise RuntimeError("Error fetching data from Have I Been Pwned API.")

    hashes = (line.split(':') for line in response.text.splitlines())
    return any(hashed_password[5:].upper() == h for h, _ in hashes)

def hash_password(password):
    sha1 = hashlib.sha1()
    sha1.update(password.encode('utf-8'))
    return sha1.hexdigest().upper()

def main():
    password = input("Enter your password: ")
    strength_info = check_password_strength(password)

    if strength_info["strength"]:
        print("Your password is strong!")
    else:
        print("Your password is weak.")
        for suggestion in strength_info["suggestions"]:
            print(f"- {suggestion}")

    if check_password_breach(password):
        print("Warning: Your password has been found in a data breach!")

if __name__ == "__main__":
    main()

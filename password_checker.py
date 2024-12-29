import re

# Function to check password strength
def check_password_strength(password):
    strength_criteria = {
        "length": len(password) >= 12,
        "uppercase": re.search(r'[A-Z]', password),
        "lowercase": re.search(r'[a-z]', password),
        "digits": re.search(r'\d', password),
        "special": re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
    }
    
    score = sum(bool(v) for v in strength_criteria.values())
    
    # Password strength levels
    if score == 5:
        return "Strong 💪"
    elif score >= 3:
        return "Moderate ⚠️"
    else:
        return "Weak ❌"

# Get password input from user
def main():
    print("🔐 Password Strength Checker")
    password = input("Enter a password to check: ")
    result = check_password_strength(password)
    print(f"Password Strength: {result}")

if __name__ == "__main__":
    main()

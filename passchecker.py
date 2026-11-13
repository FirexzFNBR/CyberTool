import argparse
import math
import re
import sys

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "abc123", "admin", "111111", "123123", "letmein",
    "welcome", "monkey", "dragon", "football", "iloveyou", "master", "sunshine", "princess", "qwertyuiop",
    "abc123", "password1", "1234", "1234567", "1234567890", "1q2w3e4r", "qazwsx", "password123",
    # im tired
}
COMMON_PATTERNS = [
    r"^\d+$",               # only digits
    r"^[a-zA-Z]+$",         # only letters
    r"(.)\1{2,}",           # repeated characters (aaa, 111)
    r"(012|123|234|345|456|567|678|789|890)",  # numeric sequences
    r"(abc|bcd|cde|def|qwe|asd|zxc)",           # keyboard sequences
]

def estimate(password: str) -> float:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)

def passcheck(password: str) -> dict:
    issues = []
    score = 0
    length = len(password)
    if length < 8:
        issues.append("Password too short (minimum recommended: 12 characters).")
    elif length < 12:
        issues.append("Password is a bit short; consider using 12+ characters.")
        score += 1
    else:
        score += 2
    checks = {
        "lowercase letter": re.search(r"[a-z]", password),
        "uppercase letter": re.search(r"[A-Z]", password),
        "number": re.search(r"[0-9]", password),
        "special symbol": re.search(r"[^a-zA-Z0-9]", password),
    }
    variety = sum(1 for v in checks.values() if v)
    score += variety
    missing = [name for name, found in checks.items() if not found]
    if missing:
        issues.append("Missing character types: " + ", ".join(missing) + ".")
    if password.lower() in COMMON_PASSWORDS:
        issues.append("This password is among the most common in the world. Never use it.")
        score = 0
    for pattern in COMMON_PATTERNS:
        if re.search(pattern, password, re.IGNORECASE):
            issues.append("Contains a predictable pattern (sequence or repetition).")
            score -= 1
            break
    entropy = estimate(password)
    score += min(int(entropy // 20), 3)
    score = max(0, min(score, 10))
    if score >= 8:
        level = "Very strong (CONGRATULATIONS!!)"
    elif score >= 6:
        level = "Strong (congrats!! but you can still improve it)"
    elif score >= 4:
        level = "Medium (its almost there!!)"
    elif score >= 2:
        level = "Weak (try to improve it)"
    else:
        level = "Very weak (please never use this password)"
    return {
        "length": length,
        "entropy_bits": round(entropy, 1),
        "score": score,
        "level": level,
        "issues": issues,
    }

def main():
    parser = argparse.ArgumentParser(description="Password strength checker.")
    parser.add_argument("--password", "-p", help="Password to analyze (avoid passing it on the command line for real use).")
    args = parser.parse_args()
    password = args.password or input("Enter the password to analyze: ")
    if not password:
        print("No password provided.")
        sys.exit(1)
    result = passcheck(password)
    print("\n=== Password Result ===")
    print(f"Length:           {result['length']}")
    print(f"Estimated entropy: {result['entropy_bits']} bits")
    print(f"Score (0-10):      {result['score']}")
    print(f"Rating:           {result['level']}")
    if result["issues"]:
        print("\nPoints to review:")
        for issue in result["issues"]:
            print(f"  - {issue}")
    else:
        print("\nNo obvious issues found. Good password!")
if __name__ == "__main__":
    main()
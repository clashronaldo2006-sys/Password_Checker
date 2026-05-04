import math
import re
import secrets
import string

COMMON_PASSWORDS = [
    "123456", "password", "admin", "qwerty", "letmein", "abc123",
    "password123", "123456789", "welcome", "iloveyou"
]

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
KEYBOARD_PATTERNS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]
ALPHABET = "abcdefghijklmnopqrstuvwxyz"
DIGITS = "0123456789"

def is_common_password(password):
    return password.lower() in COMMON_PASSWORDS


def calculate_entropy(password):
    charset = 0

    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(c in SYMBOLS for c in password):
        charset += 32

    if charset == 0:
        return 0

    entropy = len(password) * math.log2(charset)
    return round(entropy, 2)

def estimate_crack_time(entropy):
    guesses_per_second = 1_000_000_000  # 1 billion guesses/sec

    seconds = (2 ** entropy) / guesses_per_second

    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.2f} days"
    else:
        return f"{seconds/31536000:.2f} years"


def has_sequence(value, source, min_length=3):
    normalized = value.lower()
    for size in range(min_length, len(source) + 1):
        for index in range(len(source) - size + 1):
            sequence = source[index:index + size]
            if sequence in normalized or sequence[::-1] in normalized:
                return sequence
    return None


def has_predictable_pattern(password):
    if re.search(r"(.)\1{2,}", password.lower()):
        return True
    if has_sequence(password, ALPHABET, 3):
        return True
    if has_sequence(password, DIGITS, 3):
        return True
    return any(has_sequence(password, pattern, 4) for pattern in KEYBOARD_PATTERNS)


def generate_password(length=16):
    """Generate a password with character mix and no obvious predictable patterns."""
    length = min(max(length, 8), 64)
    alphabet = string.ascii_letters + string.digits + SYMBOLS

    for _ in range(100):
        required = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice(SYMBOLS),
        ]
        remaining = [secrets.choice(alphabet) for _ in range(length - 4)]
        chars = required + remaining
        secrets.SystemRandom().shuffle(chars)
        password = "".join(chars)

        if not has_predictable_pattern(password):
            return password

    return password

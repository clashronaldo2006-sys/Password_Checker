import re
from checker.utils import (
    ALPHABET,
    DIGITS,
    KEYBOARD_PATTERNS,
    SYMBOLS,
    calculate_entropy,
    estimate_crack_time,
    generate_password,
    has_sequence,
    is_common_password,
)

class PasswordAnalyzer:
    def __init__(self, password: str):
        self.password = password
        self.score = 0
        self.feedback = []
        self.detected_patterns = []

    def check_length(self):
        if len(self.password) >= 12:
            self.score += 2
        elif len(self.password) >= 8:
            self.score += 1
        else:
            self.feedback.append("Password is too short (min 8 characters)")

    def check_uppercase(self):
        if re.search(r"[A-Z]", self.password):
            self.score += 1
        else:
            self.feedback.append("Add uppercase letters")

    def check_lowercase(self):
        if re.search(r"[a-z]", self.password):
            self.score += 1
        else:
            self.feedback.append("Add lowercase letters")

    def check_numbers(self):
        if re.search(r"\d", self.password):
            self.score += 1
        else:
            self.feedback.append("Add numbers")

    def check_symbols(self):
        if any(char in SYMBOLS for char in self.password):
            self.score += 1
        else:
            self.feedback.append("Add special characters")

    def check_patterns(self):
        value = self.password.lower()

        for pattern in KEYBOARD_PATTERNS:
            found = has_sequence(self.password, pattern, 4)
            if found:
                self.detected_patterns.append(f"Keyboard pattern: {found}")
                self.feedback.append("Avoid keyboard patterns like qwerty")
                break

        alpha_sequence = has_sequence(self.password, ALPHABET, 3)
        if alpha_sequence:
            self.detected_patterns.append(f"Alphabet sequence: {alpha_sequence}")
            self.feedback.append("Avoid alphabet sequences like abc")

        number_sequence = has_sequence(self.password, DIGITS, 3)
        if number_sequence:
            self.detected_patterns.append(f"Number sequence: {number_sequence}")
            self.feedback.append("Avoid number sequences like 123")

        repeated = re.search(r"(.)\1{2,}", value)
        if repeated:
            self.detected_patterns.append(f"Repeated character: {repeated.group(0)}")
            self.feedback.append("Avoid repeating the same character three or more times")

        if self.detected_patterns:
            self.score = max(0, self.score - len(self.detected_patterns))

    def classify_strength(self, entropy):
        if self.score <= 1:
            return "Very Weak"
        if self.score <= 2 or entropy < 36:
            return "Weak"
        if self.score <= 4 or entropy < 60:
            return "Medium"
        if entropy < 80:
            return "Strong"
        return "Very Strong"

    def evaluate(self):
        if is_common_password(self.password):
            return {
                "score": 0,
                "strength": "Very Weak",
                "feedback": ["This is a commonly used password (extremely unsafe)"],
                "detected_patterns": ["Common password"],
                "suggested_password": generate_password(),
                "entropy": 0,
                "crack_time": "Instant"
           }

        self.check_length()
        self.check_uppercase()
        self.check_lowercase()
        self.check_numbers()
        self.check_symbols()
        self.check_patterns()

        entropy = calculate_entropy(self.password)
        crack_time = estimate_crack_time(entropy)

        strength = self.classify_strength(entropy)

        return {
            "score": self.score,
            "strength": strength,
            "feedback": self.feedback,
            "detected_patterns": self.detected_patterns,
            "suggested_password": generate_password(),
            "entropy": entropy,
            "crack_time": crack_time
        }   

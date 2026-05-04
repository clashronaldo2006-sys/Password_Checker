import unittest

from checker.analyzer import PasswordAnalyzer
from checker.utils import generate_password, has_predictable_pattern


class PasswordAnalyzerTests(unittest.TestCase):
    def analyze(self, password):
        return PasswordAnalyzer(password).evaluate()

    def test_detects_keyboard_pattern(self):
        result = self.analyze("qwertyA1!")
        self.assertTrue(any("Keyboard pattern" in item for item in result["detected_patterns"]))

    def test_detects_alphabet_sequence(self):
        result = self.analyze("abcDEF12!")
        self.assertTrue(any("Alphabet sequence" in item for item in result["detected_patterns"]))

    def test_detects_number_sequence(self):
        result = self.analyze("Safe123!")
        self.assertTrue(any("Number sequence" in item for item in result["detected_patterns"]))

    def test_detects_repeated_characters(self):
        result = self.analyze("AAAsecure12!")
        self.assertTrue(any("Repeated character" in item for item in result["detected_patterns"]))

    def test_generated_password_has_character_mix(self):
        password = generate_password()
        self.assertGreaterEqual(len(password), 16)
        self.assertTrue(any(char.islower() for char in password))
        self.assertTrue(any(char.isupper() for char in password))
        self.assertTrue(any(char.isdigit() for char in password))
        self.assertTrue(any(not char.isalnum() for char in password))
        self.assertFalse(has_predictable_pattern(password))

    def test_empty_password_is_very_weak(self):
        result = self.analyze("")
        self.assertEqual(result["strength"], "Very Weak")
        self.assertEqual(result["entropy"], 0)

    def test_only_symbols_is_weak_without_required_mix(self):
        result = self.analyze("!@#$%^&*")
        self.assertIn(result["strength"], ["Very Weak", "Weak", "Medium"])
        self.assertIn("Add uppercase letters", result["feedback"])
        self.assertIn("Add lowercase letters", result["feedback"])
        self.assertIn("Add numbers", result["feedback"])

    def test_very_long_password_does_not_crash(self):
        result = self.analyze("A" * 120 + "b9!")
        self.assertGreater(result["entropy"], 100)
        self.assertTrue(any("Repeated character" in item for item in result["detected_patterns"]))

    def test_unicode_input_does_not_crash(self):
        result = self.analyze("Pässwörd🔒123!")
        self.assertIn("strength", result)
        self.assertTrue(any("Number sequence" in item for item in result["detected_patterns"]))


if __name__ == "__main__":
    unittest.main()

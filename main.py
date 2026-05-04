from checker.analyzer import PasswordAnalyzer
from colorama import Fore, init


def main():
    init(autoreset=True)

    print("PASSWORD STRENGTH CHECKER")
    print("=" * 40)

    password = input("Enter your password: ")

    analyzer = PasswordAnalyzer(password)
    result = analyzer.evaluate()

    if result["strength"] in ("Very Weak", "Weak"):
        color = Fore.RED
    elif result["strength"] == "Medium":
        color = Fore.YELLOW
    else:
        color = Fore.GREEN

    print("\nRESULT")
    print("-" * 40)
    print(f"Score      : {result['score']}/6")
    print(color + f"Strength   : {result['strength']}")
    print(f"Entropy    : {result['entropy']} bits")
    print(f"Crack Time : {result['crack_time']}")

    if result["detected_patterns"]:
        print("\nDetected patterns:")
        for pattern in result["detected_patterns"]:
            print(f" - {pattern}")

    if result["feedback"]:
        print("\nSuggestions:")
        for tip in result["feedback"]:
            print(f" - {tip}")
    else:
        print("\nExcellent password!")

    print(f"\nSuggested strong password: {result['suggested_password']}")


if __name__ == "__main__":
    main()

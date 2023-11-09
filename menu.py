from enum import Enum, auto


def interactive_menu():
    while True:
        print("\n=== Hello! I am Charlotte, a friendly spider who knows the web. Please enter a number to allow "
              "me to show you around! ===")
        print("1. Discover Directories")
        print("2. Extract Forms")
        print("3. XSS Testing in Forms")
        print("4. Advanced XSS Testing in Forms")
        print("5. Time-Based SQL Injection Testing")
        print("6. XSS Testing in Links")
        print("7. SQL Injection Testing")
        print("8. SSRF Testing")
        print("9. Start complete scan")
        print("10. Exit")

        choice = input("Enter your choice: ")

        return choice


class MenuChoice(Enum):
    DISCOVER = auto()
    EXTRACT_FORMS = auto()
    XSS_IN_FORM = auto()
    ADVANCED_XSS_TESTING = auto()
    TIME_BASED_SQI = auto()
    XSS_IN_LINK = auto()
    SQLI = auto()
    SSRF = auto()
    START = auto()
    EXIT = auto()
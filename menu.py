from enum import Enum, auto


def interactive_menu():
    while True:
        print("\n=== Hello! I am Charlotte, a friendly spider who knows the web. Please enter a number to allow "
              "me to show you around! ===")
        print("1. Discover Directories")
        print("2. Extract Forms")
        print("3. XSS Testing in Forms")
        print("4. Time-Based SQL Injection Testing")
        print("5. XSS Testing in Links")
        print("6. SQL Injection Testing")
        print("7. Exit")

        choice = input("Enter your choice (1-7): ")

        return choice


class MenuChoice(Enum):
    DISCOVER = auto()
    EXTRACT_FORMS = auto()
    XSS_IN_FORM = auto()
    TIME_BASED_SQI = auto()
    XSS_IN_LINK = auto()
    SQLI = auto()
    EXIT = auto()
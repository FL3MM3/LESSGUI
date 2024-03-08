import argparse
import requests
import hashlib
import sys
import os
from tabulate import tabulate
import colorama
import tqdm
from colorama import Fore, Style
from tqdm import tqdm as tqdm_progress
import time

# Initialize colorama
colorama.init()

class PasswordChecker:
    def __init__(self):
        # API key for the Breach Directory API
        self.api_key = "YOUR-API-KEY"

    def hash_password(self, password):
        # Hash the password using SHA-1 algorithm
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        return sha1_hash

    def check_pwned_password(self, password_hash):
        url_pwned = f"https://api.pwnedpasswords.com/range/{password_hash[:5]}"

        response_pwned = requests.get(url_pwned)
        if response_pwned.status_code == 200:
            hashes = response_pwned.text.splitlines()

            with tqdm_progress(total=len(hashes), desc="Vérification des mots de passe compromis", unit="hash") as pbar:
                for h in hashes:
                    if password_hash[5:] in h:
                        count = int(h.split(":")[1])
                        return {"pwned": True, "count": count}
                    pbar.update(1)
                    time.sleep(0.001)
            return {"pwned": False, "count": 0}
        else:
            print(f"Erreur de requête pour Have I Been Pwned: {response_pwned.status_code}")
            print(response_pwned.text)
            return None

    def check_breach_directory(self, email):
        # Check if the email has been compromised using the Breach Directory API
        url_breach_directory = "https://breachdirectory.p.rapidapi.com/"
        querystring = {"func": "auto", "term": email}
        headers_breach_directory = {
            "X-RapidAPI-Key": self.api_key,
            "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
        }
        response_breach_directory = requests.get(url_breach_directory, headers=headers_breach_directory, params=querystring)

        if response_breach_directory.status_code == 200:
            return response_breach_directory.json()
        else:
            print(f"Error in request to Breach Directory: {response_breach_directory.status_code}")
            print(response_breach_directory.text)
            return None

class UserInputHandler:
    def __init__(self, args):
        # Initialize with the command line arguments
        self.args = args

    def get_password_from_user(self):
        # Get the password from the user input
        return self.args.password

    def get_email_from_user(self):
        # Get the email from the user input
        return self.args.email

    def get_file_path_from_user(self):
        # Get the file path from the user input
        return self.args.file

class ProgramExecutor:
    def __init__(self, password_checker, user_input_handler):
        # Initialize with instances of PasswordChecker and UserInputHandler
        self.password_checker = password_checker
        self.user_input_handler = user_input_handler

    def execute(self):
        # Execute the program logic
        password = self.user_input_handler.get_password_from_user()
        email = self.user_input_handler.get_email_from_user()
        file_path = self.user_input_handler.get_file_path_from_user()

        if password:
            hashed_password = self.password_checker.hash_password(password)
            result_pwned = self.password_checker.check_pwned_password(hashed_password)
            self.display_result(password, result_pwned)

        if email:
            result_breach_directory = self.password_checker.check_breach_directory(email)
            print("\nRaw result for Breach Directory:", result_breach_directory)

            if result_breach_directory:
                self.display_email_result(result_breach_directory)

        if file_path:
            passwords_to_test = self.read_passwords_from_file(file_path)
            results = {}

            for password in passwords_to_test:
                hashed_password = self.password_checker.hash_password(password)
                result_pwned = self.password_checker.check_pwned_password(hashed_password)
                results[password] = result_pwned

            self.display_file_results(results)

    def display_result(self, password, result):
        # Display the result for an individual password
        os.system("cls" if os.name == "nt" else "clear")
        print_ascii_art()
        if result["pwned"]:
            print(f"\nResult for password '{password}':")
            data_pwned = {
                "Status": ["Compromised"],
                "Frequency": [result["count"]],
                "Password": [password]
            }
        else:
            print(f"\nResult for password '{password}':")
            data_pwned = {
                "Status": ["Not Compromised"],
                "Frequency": [result["count"]],
                "Password": [password]
            }

        headers_pwned = ["Status", "Frequency", "Password"]
        table_pwned = tabulate(data_pwned, headers=headers_pwned, tablefmt="rounded_grid")
        print(table_pwned)

    def display_email_result(self, result_breach_directory):
        # Display the result for an email address
        os.system("cls" if os.name == "nt" else "clear")
        print_ascii_art()
        if result_breach_directory["found"]:
            print(f"\nInformation on compromised email address:")

            if 'result' in result_breach_directory:
                data_email = []
                for breach_result in result_breach_directory['result']:
                    data_email.append([
                        breach_result.get('email', "N/A"),
                        str(breach_result.get('hash_password', "N/A")),
                        breach_result.get('password', "N/A"),
                        breach_result.get('sha1', "N/A"),
                        breach_result.get('hash', "N/A")
                    ])

                headers_email = ["Attribute", "hash_password", "password", "sha1", "hash"]
                table_email = tabulate(data_email, headers=headers_email, tablefmt="rounded_grid")
                print(table_email)
            else:
                print("The 'result' key is not present in the API response.")
        else:
            print("\nThe email address has not been compromised on Breach Directory. That's good news!")

    def display_file_results(self, results):
        # Display the result for each password in a file
        os.system("cls" if os.name == "nt" else "clear")
        print_ascii_art()
        for password, result in results.items():
            print(f"\nResult for password '{password}':")
            self.display_pwned_result_file(result)

    def read_passwords_from_file(self, file_path):
        # Read passwords from a file
        with open(file_path, 'r') as file:
            return [line.strip() for line in file]

    def display_pwned_result_file(self, result):
        # Display the result for a password in a file
        if result["pwned"]:
            print("\nPassword compromised on Have I Been Pwned:")
            data_pwned = {
                "Status": ["Compromised"],
                "Frequency": [result["count"]]
            }
        else:
            print("\nPassword not compromised on Have I Been Pwned. That's good news!")

        headers_pwned = ["Status", "Frequency"]
        table_pwned = tabulate(data_pwned, headers=headers_pwned, tablefmt="rounded_grid")
        print(table_pwned)

def print_ascii_art():
    print(Fore.LIGHTBLUE_EX + '''
██▓   ▓█████  ██████  ██████  ▄████ █    ██ ██▓
▓██▒   ▓█   ▀▒██    ▒▒██    ▒ ██▒ ▀█▒██  ▓██▓██▒
▒██░   ▒███  ░ ▓██▄  ░ ▓██▄  ▒██░▄▄▄▓██  ▒██▒██▒
▒██░   ▒▓█  ▄  ▒   ██▒ ▒   ██░▓█  ██▓▓█  ░██░██░
░██████░▒████▒██████▒▒██████▒░▒▓███▀▒▒█████▓░██░
░ ▒░▓  ░░ ▒░ ▒ ▒▓▒ ▒ ▒ ▒▓▒ ▒ ░░▒   ▒░▒▓▒ ▒ ▒░▓  
░ ░ ▒  ░░ ░  ░ ░▒  ░ ░ ░▒  ░ ░ ░   ░░░▒░ ░ ░ ▒ ░
  ░ ░     ░  ░     ░       ░       ░   ░     ░  
author : flem, fukuda
github : https://github.com/FL3MM3
______________________________________________
'''.strip() + Style.RESET_ALL)

def main():
    parser = argparse.ArgumentParser(description="Check the security of passwords and e-mail addresses.")
    parser.add_argument('-p', '--password', help="Password to check.")
    parser.add_argument('-e', '--email', help="Email to check.")
    parser.add_argument('-f', '--file', help="Path to the file containing the passwords to be tested.")
    args = parser.parse_args()

    password_checker = PasswordChecker()
    user_input_handler = UserInputHandler(args)
    program_executor = ProgramExecutor(password_checker, user_input_handler)

    if len(sys.argv) == 1:
        os.system("cls" if os.name == "nt" else "clear")
        print_ascii_art()
        print("Help:")
        parser.print_help()
    else:
        program_executor.execute()

if __name__ == "__main__":
    main()

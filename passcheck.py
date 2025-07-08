import re
import json
import hashlib
import secrets
import string
import getpass
import requests
import time
import threading
import sys
from datetime import datetime
from pyfiglet import figlet_format
from colorama import Fore, Style, init
import argparse
import os

init(autoreset=True)

class LoadingSpinner:
    def __init__(self, message="Processing"):
        self.message = message
        self.spinner_chars = ['-', '\\', '|', '/']
        self.stop_spinner = False
        self.spinner_thread = None
        
    def start(self):
        self.stop_spinner = False
        self.spinner_thread = threading.Thread(target=self._spin)
        self.spinner_thread.start()
        
    def stop(self):
        self.stop_spinner = True
        if self.spinner_thread:
            self.spinner_thread.join()
        print('\r' + ' ' * (len(self.message) + 4), end='\r')
        
    def _spin(self):
        idx = 0
        while not self.stop_spinner:
            char = self.spinner_chars[idx % len(self.spinner_chars)]
            print(f'\r{char} {self.message}...', end='', flush=True)
            time.sleep(0.15)
            idx += 1

class PassCheck:
    def __init__(self):
        self.history = []
        self.history_file = 'passcheck_history.json'
        self.load_history()

    def generate_secure_password(self, length=16, exclude_ambiguous=False):
        base_chars = string.ascii_letters + string.digits + "!@#$%^&*"
        
        if exclude_ambiguous:
            for char in '0OlI1':
                base_chars = base_chars.replace(char, '')
        
        # Ensure at least one character from each required type
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits.replace('0', '') if exclude_ambiguous else string.digits),
            secrets.choice("!@#$%^&*")
        ]
        
        # Fill remaining length with random characters
        for _ in range(length - 4):
            password.append(secrets.choice(base_chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)

    def check_password_strength(self, password):
        score = 0
        feedback = []
        warnings = []

        # Length scoring
        if len(password) >= 16:
            score += 35
            feedback.append("Excellent length (16+ characters)")
        elif len(password) >= 12:
            score += 25
            feedback.append("Good length (12-15 characters)")
        elif len(password) >= 8:
            score += 15
            feedback.append("Minimum acceptable length")
        else:
            warnings.append("Too short - use at least 8 characters")

        # Character type checks
        if re.search(r'[a-z]', password):
            score += 10
            feedback.append("Contains lowercase letters")
        else:
            warnings.append("Add lowercase letters")

        if re.search(r'[A-Z]', password):
            score += 10
            feedback.append("Contains uppercase letters")
        else:
            warnings.append("Add uppercase letters")

        if re.search(r'\d', password):
            score += 10
            feedback.append("Contains numbers")
        else:
            warnings.append("Add numbers")

        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 15
            feedback.append("Contains special characters")
        else:
            warnings.append("Add special characters")

        # Character diversity (only for passwords 8+ characters)
        if len(password) >= 8:
            unique_ratio = len(set(password)) / len(password)
            if unique_ratio > 0.8:
                score += 15
                feedback.append("Excellent character diversity")
            elif unique_ratio > 0.6:
                score += 10
                feedback.append("Good character diversity")
            else:
                warnings.append("Too many repeated characters")
        else:
            # For short passwords, always flag as low diversity
            warnings.append("Password too short for proper diversity")

        # Pattern penalties
        if re.search(r'(123|abc|qwe|asd|zxc|password|admin)', password.lower()):
            score -= 15
            warnings.append("Contains common patterns or words")

        if re.search(r'(19|20)\d{2}', password):
            score -= 10
            warnings.append("Avoid using dates")

        return max(0, min(100, score)), feedback, warnings

    def check_breach_status(self, password):
        try:
            # Create SHA1 hash
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Query HaveIBeenPwned API
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            headers = {'User-Agent': 'PassCheck-Security-Tool'}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                for line in response.text.splitlines():
                    hash_suffix, count = line.split(':')
                    if hash_suffix == suffix:
                        return True, int(count)
                return False, 0
            else:
                return None, 0
                
        except requests.RequestException:
            return None, 0

    def get_strength_rating(self, score):
        if score >= 90:
            return "EXCELLENT", Fore.GREEN
        elif score >= 70:
            return "STRONG", Fore.CYAN
        elif score >= 50:
            return "MODERATE", Fore.YELLOW
        elif score >= 30:
            return "WEAK", Fore.RED
        else:
            return "VERY WEAK", Fore.RED

    def save_history(self):
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.history, f, indent=2)
        except Exception:
            pass

    def load_history(self):
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    self.history = json.load(f)
        except Exception:
            self.history = []

    def add_to_history(self, score, rating, breach_status):
        entry = {
            'timestamp': datetime.now().isoformat(),
            'score': score,
            'rating': rating,
            'breach_status': breach_status
        }
        self.history.append(entry)
        if len(self.history) > 50:
            self.history = self.history[-50:]
        self.save_history()

    def show_history(self):
        if not self.history:
            print("No analysis history found.")
            return

        print("\nPassword Analysis History")
        print("-" * 50)
        
        for i, entry in enumerate(self.history[-10:], 1):
            timestamp = datetime.fromisoformat(entry['timestamp'])
            rating_color = self.get_strength_rating(entry['score'])[1]
            print(f"{i:2d}. {timestamp.strftime('%Y-%m-%d %H:%M')} | "
                  f"{rating_color}{entry['rating']:<12}{Style.RESET_ALL} | "
                  f"{entry['score']:3d}/100 | "
                  f"{entry['breach_status']}")

    def show_banner(self):
        print(Fore.CYAN + figlet_format("PassCheck", font="slant") + Style.RESET_ALL)
        print(f"{Fore.YELLOW}Professional Security Assessment | Built by Paul{Style.RESET_ALL}")
        print("-" * 50)

    def analyze_password_interactive(self):
        print(f"\n{Fore.CYAN}Password Analysis{Style.RESET_ALL}")
        print("Enter password to analyze (input will be hidden):")
        password = getpass.getpass("Password: ")
        
        if not password:
            print(f"{Fore.RED}No password entered.{Style.RESET_ALL}")
            return

        # Step 1: Analyze strength
        spinner = LoadingSpinner("Analyzing password strength")
        spinner.start()
        time.sleep(1)
        score, feedback, warnings = self.check_password_strength(password)
        rating, rating_color = self.get_strength_rating(score)
        spinner.stop()
        print("Password strength analysis complete")

        # Step 2: Check breach status
        spinner = LoadingSpinner("Checking breach databases")
        spinner.start()
        time.sleep(1)
        breach_status, breach_count = self.check_breach_status(password)
        spinner.stop()
        print("Breach database check complete")

        # Display results
        print(f"\n{'-' * 50}")
        print("PASSWORD SECURITY ASSESSMENT")
        print(f"{'-' * 50}")
        
        print(f"Overall Score: {Fore.YELLOW}{score}/100{Style.RESET_ALL}")
        print(f"Strength Rating: {rating_color}{rating}{Style.RESET_ALL}")

        if feedback:
            print(f"\n{Fore.GREEN}Strengths:{Style.RESET_ALL}")
            for item in feedback:
                print(f"  • {item}")

        if warnings:
            print(f"\n{Fore.YELLOW}Recommendations:{Style.RESET_ALL}")
            for item in warnings:
                print(f"  • {item}")

        # Breach status
        print(f"\n{Fore.CYAN}Breach Status:{Style.RESET_ALL}")
        if breach_status is None:
            print(f"  {Fore.YELLOW}Could not verify (service unavailable){Style.RESET_ALL}")
            breach_text = "Unknown"
        elif breach_status:
            print(f"  {Fore.RED}COMPROMISED - Found in {breach_count:,} breaches{Style.RESET_ALL}")
            print(f"  {Fore.RED}Recommendation: Change this password immediately{Style.RESET_ALL}")
            breach_text = "Compromised"
        else:
            print(f"  {Fore.GREEN}No known breaches found{Style.RESET_ALL}")
            breach_text = "Clean"

        print(f"{'-' * 50}")
        self.add_to_history(score, rating, breach_text)

    def generate_password_interactive(self):
        print(f"\n{Fore.CYAN}Password Generation{Style.RESET_ALL}")
        
        print("1. Quick Generate (recommended)")
        print("2. Custom Options")
        
        choice = input("Select (1-2, default 1): ").strip()
        
        if choice == '2':
            length_input = input("Length (8-64, default 16): ").strip()
            
            try:
                length = int(length_input) if length_input else 16
                if length < 8:
                    print(f"{Fore.YELLOW}Minimum length is 8. Using 8 characters.{Style.RESET_ALL}")
                    length = 8
                elif length > 64:
                    print(f"{Fore.YELLOW}Maximum length is 64. Using 64 characters.{Style.RESET_ALL}")
                    length = 64
            except ValueError:
                length = 16
                print(f"{Fore.YELLOW}Invalid length. Using default (16).{Style.RESET_ALL}")
        else:
            length = 16
        
        # Always use standard password requirements (no ambiguous character exclusion)
        exclude_ambiguous = False

        # Generate password
        spinner = LoadingSpinner("Generating secure password")
        spinner.start()
        time.sleep(0.5)
        password = self.generate_secure_password(length, exclude_ambiguous)
        spinner.stop()
        
        print("Password generated successfully")
        print(f"\nGenerated Password: {Fore.YELLOW}{password}{Style.RESET_ALL}")
        
        # Quick strength check
        score, _, _ = self.check_password_strength(password)
        rating, rating_color = self.get_strength_rating(score)
        print(f"Strength: {rating_color}{rating}{Style.RESET_ALL} ({score}/100)")
        print(f"{Fore.CYAN}Tip: Copy this password to secure location{Style.RESET_ALL}")

    def run(self):
        self.show_banner()

        while True:
            print(f"\n{Fore.GREEN}Main Menu{Style.RESET_ALL}")
            print("1. Check Password Strength")
            print("2. Generate Secure Password")
            print("3. View Analysis History")
            print("4. Exit")

            user_choice = input(f"\nSelect option (1-4): ").strip()

            if user_choice == '1':
                self.analyze_password_interactive()
            elif user_choice == '2':
                self.generate_password_interactive()
            elif user_choice == '3':
                self.show_history()
            elif user_choice == '4':
                print(f"\n{Fore.GREEN}Thank you for using PassCheck!{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}Invalid option. Please select 1-4.{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="PassCheck - Password Security Tool")
    parser.add_argument("--version", action="version", version="PassCheck 1.0")
    parser.add_argument("--generate", "-g", type=int, metavar="LENGTH", 
                       help="Generate a secure password of specified length")
    parser.add_argument("--no-ambiguous", action="store_true",
                       help="Exclude ambiguous characters when generating passwords")
    
    args = parser.parse_args()
    
    # Command line password generation
    if args.generate:
        checker = PassCheck()
        password = checker.generate_secure_password(args.generate, args.no_ambiguous)
        print(f"Generated password: {password}")
        return
    
    # Interactive mode
    try:
        checker = PassCheck()
        checker.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Goodbye!{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
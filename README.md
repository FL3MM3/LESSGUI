# LESSGUI

LESSGUI is a Python tool designed to enhance password security by checking the compromise status of passwords and email addresses. This tool utilizes the Have I Been Pwned API and the Breach Directory API to provide comprehensive security assessments.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/FL3MM3/LESSGUI.git
   ```

2. Navigate to the project directory:
   ```bash
   cd LESSGUI
   ```

3. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Obtain API keys:

   - **Have I Been Pwned API Key:**
     - Visit [Have I Been Pwned](https://haveibeenpwned.com/API/Key) to obtain your API key.
     - Replace `'YOUR_HIBP_API_KEY'` in the `check_pwned_password` function with your actual API key.

   - **Breach Directory API Key:**
     - Visit [RapidAPI](https://rapidapi.com/) and sign up for an account.
     - Subscribe to the "Breach Directory" API to obtain your API key.
     - Replace `'YOUR_BREACH_DIRECTORY_API_KEY'` in the `headers_breach_directory` dictionary with your actual API key.

5. Run the script:
   ```bash
   python lessgui.py
   ```

## Usage

### Check a Password

To check the security of a single password, use the `-p` or `--password` option followed by the desired password:

```bash
python lessgui.py -p your_password_here
```

### Check an Email Address

To check if an email address has been compromised, use the `-e` or `--email` option followed by the email address:

```bash
python lessgui.py -e your_email@example.com
```

### Check Passwords from a File

To check a list of passwords stored in a file, use the `-f` or `--file` option followed by the path to the file:

```bash
python lessgui.py -f path/to/passwords.txt
```

### Help

If you need assistance or want to view the available options, run the script without any arguments:

```bash
python lessgui.py
```

This will display the help information, providing details on how to use the LESSGUI tool.

## Authors

- [flem](https://github.com/FL3MM3)
- [fukuda](https://github.com/fukuda)

## Acknowledgments

Special thanks to the creators of [Have I Been Pwned](https://haveibeenpwned.com/) and [Breach Directory](https://breachdirectory.com/) for providing valuable APIs to enhance password security.

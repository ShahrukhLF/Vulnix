#!/usr/bin/env python3

import requests
import sys
import warnings
from bs4 import BeautifulSoup

# Suppress insecure request warnings for target sites without SSL
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

def get_authenticated_cookie(login_url, username, password):
    # Start a persistent session (this remembers cookies automatically)
    session = requests.Session()
    
    try:
        # Step 1: Visit the login page to get initial cookies and hidden form tokens
        response = session.get(login_url, verify=False, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find the first form on the page (usually the login form)
        form = soup.find('form')
        if not form:
            print("ERROR: No login form found on the provided URL.")
            sys.exit(1)

        # Step 2: Extract all input fields from the form
        data = {}
        for input_tag in form.find_all('input'):
            input_name = input_tag.get('name')
            input_type = input_tag.get('type', 'text').lower()
            input_value = input_tag.get('value', '')

            if not input_name:
                continue
            
            # Smart Heuristics: Catch 'login', 'uid', 'user', and 'email'
            name_lower = input_name.lower()
            
            # Check for username field
            if input_type in ['text', 'email'] and any(keyword in name_lower for keyword in ['user', 'email', 'login', 'uid']):
                data[input_name] = username
            # Check for password field
            elif input_type == 'password' or 'pass' in name_lower:
                data[input_name] = password
            # Keep everything else (like submit buttons and CSRF tokens)
            else:
                data[input_name] = input_value

        # Step 3: Determine where the form submits to (action attribute)
        action = form.get('action')
        if action:
            if action.startswith('http'):
                submit_url = action
            else:
                # Handle relative URLs (e.g., action="login.php")
                base_url = login_url.rsplit('/', 1)[0]
                submit_url = f"{base_url}/{action.lstrip('/')}"
        else:
            submit_url = login_url

        # Step 4: Submit the login payload
        login_response = session.post(submit_url, data=data, verify=False, allow_redirects=False)

        # Step 5: Format the stolen cookies for SQLMap and ZAP
        cookies = session.cookies.get_dict()
        if not cookies:
            print("ERROR: Authentication failed. No session cookies received.")
            sys.exit(1)

        # CRITICAL FIX: Removed the space after the semicolon to prevent Bash word-splitting
        cookie_string = ";".join([f"{k}={v}" for k, v in cookies.items()])
        print(f"SUCCESS|{cookie_string}")
        sys.exit(0)

    except Exception as e:
        print(f"ERROR: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 auto_login.py <login_url> <username> <password>")
        sys.exit(1)
        
    target_url = sys.argv[1]
    user = sys.argv[2]
    pw = sys.argv[3]
    
    get_authenticated_cookie(target_url, user, pw)

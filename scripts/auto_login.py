#!/usr/bin/env python3
"""
Vulnix Automated Authentication Module.
Dynamically parses login forms, applies field heuristics, and extracts 
authenticated session cookies for downstream DAST orchestration.
"""

import requests
import sys
import warnings
from bs4 import BeautifulSoup

# Suppress insecure request warnings for self-signed or unverified SSL targets
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

def get_authenticated_cookie(login_url, username, password):
    """Executes automated login and returns the formatted session cookie string."""
    session = requests.Session()
    
    try:
        # Retrieve initial session cookies and form tokens
        response = session.get(login_url, verify=False, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        form = soup.find('form')
        if not form:
            print("ERROR: No login form found on the provided URL.")
            sys.exit(1)

        data = {}
        for input_tag in form.find_all('input'):
            input_name = input_tag.get('name')
            input_type = input_tag.get('type', 'text').lower()
            input_value = input_tag.get('value', '')

            if not input_name:
                continue
            
            # Apply heuristics to map credentials to dynamic field names
            name_lower = input_name.lower()
            if input_type in ['text', 'email'] and any(keyword in name_lower for keyword in ['user', 'email', 'login', 'uid']):
                data[input_name] = username
            elif input_type == 'password' or 'pass' in name_lower:
                data[input_name] = password
            else:
                # Preserve hidden fields, CSRF tokens, and submit actions
                data[input_name] = input_value

        # Resolve form submission endpoint (handling relative paths)
        action = form.get('action')
        if action:
            if action.startswith('http'):
                submit_url = action
            else:
                base_url = login_url.rsplit('/', 1)[0]
                submit_url = f"{base_url}/{action.lstrip('/')}"
        else:
            submit_url = login_url

        # Execute authentication request
        login_response = session.post(submit_url, data=data, verify=False, allow_redirects=False)

        # Extract and format session cookies for downstream engines
        cookies = session.cookies.get_dict()
        if not cookies:
            print("ERROR: Authentication failed. No session cookies received.")
            sys.exit(1)

        # Format strictly without spaces to prevent bash word-splitting in orchestrator scripts
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

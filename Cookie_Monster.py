import requests
from bs4 import BeautifulSoup
import re
import datetime
import jwt

# Function to scan website for session IDs, cookies, and tokens
def scan_website(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Extract session ID from cookies
    session_id = response.cookies.get('sessionid')
    if session_id:
        print(f"[*] Session ID: {session_id}")
        analyze_session_id(session_id)

    # Extract all cookies
    cookies = response.cookies
    if cookies:
        for cookie in cookies:
            print(f"[*] Cookie: {cookie.name} = {cookie.value}")
            analyze_cookie(cookie)

    # Extract CSRF tokens
    csrf_tokens = soup.find_all('input', {'name': 'csrf_token'})
    if csrf_tokens:
        for token in csrf_tokens:
            print(f"[*] CSRF Token: {token.get('value')}")

    # Extract XSRF tokens
    xsrf_tokens = soup.find_all('input', {'name': '_xsrf'})
    if xsrf_tokens:
        for token in xsrf_tokens:
            print(f"[*] XSRF Token: {token.get('value')}")

    # Extract JWT tokens from scripts (if embedded)
    scripts = soup.find_all('script')
    for script in scripts:
        if 'jwt' in script.text:
            print(f"[*] JWT Token: {script.text.strip()}")
            analyze_jwt(script.text.strip())

def analyze_session_id(session_id):
    # Placeholder: Add logic to analyze session ID (e.g., length, entropy)
    print(f"[!] Analyzing Session ID: {session_id}")
    if len(session_id) < 20:
        print("[!] Warning: Session ID might be too short.")
    if re.match(r'^[a-zA-Z0-9]{10,}$', session_id):
        print("[!] Warning: Session ID might be predictable.")

def analyze_cookie(cookie):
    # Analyze cookie attributes
    print(f"[!] Analyzing Cookie: {cookie.name}")
    if not cookie.secure:
        print("[!] Warning: Cookie is not marked as 'Secure'.")
    if not cookie.httponly:
        print("[!] Warning: Cookie is not marked as 'HttpOnly'.")

def analyze_jwt(jwt_token):
    try:
        decoded_token = jwt.decode(jwt_token, options={"verify_signature": False})
        print(f"[!] Analyzing JWT Token: {decoded_token}")
        if 'alg' not in decoded_token or decoded_token['alg'] not in ['HS256', 'RS256']:
            print("[!] Warning: Weak or unsupported JWT algorithm.")
        if 'exp' in decoded_token:
            expiry_date = datetime.datetime.fromtimestamp(decoded_token['exp'])
            print(f"[!] JWT Expiry Date: {expiry_date}")
            if expiry_date < datetime.datetime.now():
                print("[!] Warning: JWT Token has expired.")
    except jwt.PyJWTError as e:
        print(f"[!] Error decoding JWT: {e}")

def main(url):
    print(f"[*] Scanning website: {url}")
    scan_website(url)
    print("\n[*] Cookie_Monster - Built by DeadmanXXXII")

if __name__ == "__main__":
    url = "https://example.com"  # URL of the website to scan
    main(url)

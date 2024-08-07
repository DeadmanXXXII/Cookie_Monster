
# Cookie_Monster

**Cookie_Monster** is a Python tool designed to capture and analyze session IDs, cookies, and web tokens from websites. It scans a provided URL to extract these details and performs basic analysis to identify potential vulnerabilities or types of tokens and cookies.

## Features

- **Extracts Cookies and Tokens**: Retrieves cookies and tokens from HTTP headers and JavaScript embedded in the page.
- **Basic Analysis**: Identifies whether extracted cookies or tokens might be session-related or authentication-related.
- **Command-Line Interface**: Run the script from the command line with a single URL parameter.

## Installation

1. Ensure you have Python installed on your machine.
2. Install the required Python packages using the following command:

   ```bash
   pip install -r requirements.txt
   ```

   Where `requirements.txt` should include the following:

   ```
   requests==2.28.2
   beautifulsoup4==4.12.2
   ```

## Usage

Run the script from the command line by providing the URL you want to scan. Example usage:

```bash
python Cookie_Monster.py http://example.com
```

### Arguments

- `<URL>`: The website URL to scan.

## Example Output

Here's an example of what the output might look like:

```plaintext
[*] Scanning website: http://example.com
[*] Cookie: session_id = abc123
Analyzing Cookie: session_id
[!] Cookie may be a session cookie.

[*] Token: auth_token = xyz789
Analyzing Token: auth_token
[!] Token may be an authentication token.
```

## Analysis Details

- **Cookies**:
  - If the cookie name contains 'session', it might be a session cookie.
  - If the cookie name contains 'token', it might be a token.

- **Tokens**:
  - If the token name contains 'session', it might be a session token.
  - If the token name contains 'auth', it might be an authentication token.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

Built by DeadmanXXXII.
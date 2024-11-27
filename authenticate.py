from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import json
import os


SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate():
    creds = None

    # Check if token.json exists
    if os.path.exists('token.json'):
        with open('token.json', 'r') as token_file:
            creds_data = json.load(token_file)
            creds = Credentials.from_authorized_user_info(creds_data, SCOPES)

    # If no valid credentials are available, prompt for login
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES
            )
            # Add prompt='consent' to force Google to show the consent screen
            creds = flow.run_local_server(port=8080, prompt='consent')

        # Save the credentials for future use
        with open('token.json', 'w') as token_file:
            json.dump(json.loads(creds.to_json()), token_file)

    # Ensure the token includes a refresh_token
    if not creds.refresh_token:
        raise ValueError("Authentication failed. Refresh token is missing.")

    return creds

if __name__ == "__main__":
    authenticate()
    print("Authentication successful! Token saved to token.json.")

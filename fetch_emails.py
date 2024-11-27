from googleapiclient.discovery import build
from datetime import datetime
from google.oauth2.credentials import Credentials
import json, os
from tabulate import tabulate
import base64
import requests
from termcolor import colored
from dotenv import load_dotenv
import time


# Load environment variables from .env file
load_dotenv()


# Load your VirusTotal API key from environment variables
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# VirusTotal API URL
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files"



def scan_attachment(file_data, file_name):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    files = {"file": (file_name, file_data)}

    # Step 1: Submit file for analysis
    response = requests.post(VIRUSTOTAL_URL, headers=headers, files=files)
    if response.status_code != 200:
        print(f"Error submitting {file_name}: {response.status_code}, {response.json()}")
        return False

    result = response.json()
    if "data" not in result or "id" not in result["data"]:
        print(f"Unexpected response format for {file_name}: {result}")
        return False

    analysis_id = result["data"]["id"]

    # Step 2: Poll for analysis results
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    for _ in range(10):  # Poll up to 10 times
        time.sleep(5)  # Wait 5 seconds before polling again
        analysis_response = requests.get(analysis_url, headers=headers)
        if analysis_response.status_code != 200:
            print(f"Error fetching analysis for {file_name}: {analysis_response.status_code}")
            return False

        analysis_result = analysis_response.json()
        if "data" in analysis_result and "attributes" in analysis_result["data"]:
            # Step 3: Check for malicious detections
            stats = analysis_result["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            return malicious == 0  # Safe if no malicious detections

        # If the analysis is still in progress, continue polling
        if analysis_result.get("meta", {}).get("status") == "in-progress":
            continue

    print(f"Analysis timed out for {file_name}.")
    return False

# def scan_attachment(file_data, file_name):
#     """
#     Sends an attachment to VirusTotal for scanning and returns the safety status.
#     """
#     headers = {"x-apikey": VIRUSTOTAL_API_KEY}
#     files = {"file": (file_name, file_data)}
#     response = requests.post(VIRUSTOTAL_URL, headers=headers, files=files)

#     if response.status_code == 200:
#         result = response.json()
#         print(json.dumps(result, indent=2))
#         malicious = result["data"]["attributes"]["last_analysis_stats"]["malicious"]
#         if malicious > 0:
#             return False  # Not safe
#         return True  # Safe
#     else:
#         print(f"Error scanning {file_name}: {response.status_code}, {response.text}")
#         return None  # Unable to determine safety


def authenticate():
    """Load credentials from token.json."""
    if not os.path.exists('token.json'):
        raise FileNotFoundError("Token file not found. Run authenticate.py first to generate token.json.")
    with open('token.json', 'r') as token_file:
        creds_data = json.load(token_file)
        return Credentials.from_authorized_user_info(creds_data, ['https://www.googleapis.com/auth/gmail.readonly'])


def fetch_todays_emails():
    """
    Fetch today's emails and display them in a table with attachment safety.
    """
    # Authenticate and build the Gmail service
    creds = authenticate()
    service = build('gmail', 'v1', credentials=creds)

    # Get today's date in RFC 3339 format
    today = datetime.utcnow().strftime('%Y/%m/%d')
    query = f"after:{today}"

    # Fetch messages
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])

    if not messages:
        print("No emails found for today.")
        return

    print(f"Found {len(messages)} emails for today.")

    email_data = []

    # Fetch email details
    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        
        # Extract headers
        headers = msg['payload'].get('headers', [])
        subject = ""
        sender = ""
        for header in headers:
            if header['name'] == 'Subject':
                subject = header['value']
            elif header['name'] == 'From':
                sender = header['value']

        # Extract body snippet
        snippet = msg.get('snippet', 'No snippet available')[:20]  # First 20 characters of the body

        # Check for attachments
        has_attachment = False
        safe_status = ""
        parts = msg['payload'].get('parts', [])

        for part in parts:
            if part.get('filename'):  # If there's a filename, it's an attachment
                has_attachment = True
                attachment_id = part['body'].get('attachmentId')
                if attachment_id:
                    attachment = (
                        service.users()
                        .messages()
                        .attachments()
                        .get(userId='me', messageId=message['id'], id=attachment_id)
                        .execute()
                    )
                    file_data = base64.urlsafe_b64decode(attachment['data'])
                    file_name = part['filename']

                    # Scan attachment with VirusTotal
                    is_safe = scan_attachment(file_data, file_name)
                    if is_safe is None:
                        safe_status = "Unknown"
                    elif is_safe:
                        safe_status = colored("YES", "green")
                    else:
                        safe_status = colored("NO", "red")

        # Add row to email data
        email_data.append([
            sender[:10],              # Sender
            subject[:15],             # Subject
            snippet,             # Body (20 chars)
            "Yes" if has_attachment else "No",  # Has Attachment
            safe_status if has_attachment else "",  # Safe column
        ])

    # Display the data as a table
    headers = ["Sender", "Subject", "Body (20 chars)", "Has Attachment", "Safe"]
    print(tabulate(email_data, headers=headers, tablefmt="grid"))


if __name__ == "__main__":
    fetch_todays_emails()

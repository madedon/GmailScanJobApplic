"""Scan a Gmail account for job application emails.

The script authenticates with Gmail using OAuth, searches for messages
from the last six months by default, and extracts basic job application
information. Results are printed and written to ``job_applications.csv``.
Use ``--months`` to adjust the search window. The script also detects
responses from addresses containing ``MyWorkday``.
"""

import os
import base64
import re
import argparse
import pandas as pd
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

JOB_KEYWORDS = ["job", "application", "career"]

# Replies from "MyWorkday" should also be captured
WORKDAY_KEYWORD = "myworkday"

JOB_APP_PATTERN = re.compile(r"Application\s*ID\s*[:\-]\s*(\S+)", re.IGNORECASE)


def authenticate():
    creds = None
    if not os.path.exists('credentials.json'):
        raise FileNotFoundError(
            'credentials.json not found. Download it from the Google Cloud '
            'Console and place it in this directory.'
        )
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    service = build('gmail', 'v1', credentials=creds)
    return service


def query_messages(service, months: int) -> list:
    """Return all messages from the last ``months`` months."""
    query = f'newer_than:{months}m'
    messages = []
    page_token = None
    while True:
        resp = (
            service.users()
            .messages()
            .list(userId='me', q=query, pageToken=page_token)
            .execute()
        )
        messages.extend(resp.get('messages', []))
        page_token = resp.get('nextPageToken')
        if not page_token:
            break
    return messages


def get_message_detail(service, msg_id):
    msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    payload = msg.get('payload', {})
    headers = payload.get('headers', [])
    subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
    from_header = next((h['value'] for h in headers if h['name'] == 'From'), '')
    date_str = next((h['value'] for h in headers if h['name'] == 'Date'), '')
    date = pd.to_datetime(date_str)
    parts = payload.get('parts', [])
    body = ''
    if parts:
        for part in parts:
            if part.get('mimeType') == 'text/plain':
                data = part.get('body', {}).get('data')
                if data:
                    body = base64.urlsafe_b64decode(data).decode('utf-8')
                break
    else:
        data = payload.get('body', {}).get('data')
        if data:
            body = base64.urlsafe_b64decode(data).decode('utf-8')
    return subject, body, date, from_header


def extract_job_info(subject, body, sender):
    text = subject + '\n' + body
    if not any(k.lower() in text.lower() for k in JOB_KEYWORDS) and WORKDAY_KEYWORD not in sender.lower():
        return None
    match = JOB_APP_PATTERN.search(text)
    app_code = match.group(1) if match else ''
    # Very naive extraction heuristics
    job_title_match = re.search(r"for\s+(?:the\s+)?(.*)\s+position", text, re.IGNORECASE)
    job_title = job_title_match.group(1) if job_title_match else ''
    company_match = re.search(r"at\s+([A-Za-z0-9 &]+)", text)
    company = company_match.group(1).strip() if company_match else ''
    return app_code, job_title, company


def scan_job_applications(months: int) -> None:
    """Scan Gmail for job applications in the last ``months`` months."""
    service = authenticate()
    messages = query_messages(service, months)
    rows = []
    for m in messages:
        subject, body, date, sender = get_message_detail(service, m['id'])
        info = extract_job_info(subject, body, sender)
        if info:
            app_code, job_title, company = info
            rows.append({
                'application_code': app_code,
                'date': date.strftime('%Y-%m-%d'),
                'company': company,
                'job_title': job_title,
            })
    df = pd.DataFrame(rows)
    print(df)
    if not df.empty:
        df.to_csv('job_applications.csv', index=False)
        print('Saved to job_applications.csv')

def main() -> None:
    parser = argparse.ArgumentParser(description="Scan Gmail for job applications")
    parser.add_argument(
        "--months",
        type=int,
        default=6,
        help="How many months of emails to search (default: 6)",
    )
    args = parser.parse_args()
    scan_job_applications(args.months)


if __name__ == '__main__':
    main()

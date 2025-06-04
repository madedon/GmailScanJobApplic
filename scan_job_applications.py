 (cd "$(git rev-parse --show-toplevel)" && git apply --3way <<'EOF' 
diff --git a//dev/null b/scan_job_applications.py
index 0000000000000000000000000000000000000000..fc4cb0a0bbd3f35e5ad93a77dd7b6a7c1123fead 100644
--- a//dev/null
+++ b/scan_job_applications.py
@@ -0,0 +1,114 @@
+"""Scan a Gmail account for job application emails.
+
+The script authenticates with Gmail using OAuth, searches for messages
+from the last six months, and tries to extract basic job application
+information. Results are printed and written to ``job_applications.csv``.
+"""
+
+import os
+import base64
+import re
+import pandas as pd
+from google.auth.transport.requests import Request
+from google.oauth2.credentials import Credentials
+from google_auth_oauthlib.flow import InstalledAppFlow
+from googleapiclient.discovery import build
+
+SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
+
+JOB_KEYWORDS = ["job", "application", "career"]
+
+JOB_APP_PATTERN = re.compile(r"Application\s*ID\s*[:\-]\s*(\S+)", re.IGNORECASE)
+
+
+def authenticate():
+    creds = None
+    if not os.path.exists('credentials.json'):
+        raise FileNotFoundError(
+            'credentials.json not found. Download it from the Google Cloud '
+            'Console and place it in this directory.'
+        )
+    if os.path.exists('token.json'):
+        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
+    if not creds or not creds.valid:
+        if creds and creds.expired and creds.refresh_token:
+            creds.refresh(Request())
+        else:
+            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
+            creds = flow.run_local_server(port=0)
+        with open('token.json', 'w') as token:
+            token.write(creds.to_json())
+    service = build('gmail', 'v1', credentials=creds)
+    return service
+
+
+def query_messages(service):
+    query = 'newer_than:6m'
+    results = service.users().messages().list(userId='me', q=query).execute()
+    messages = results.get('messages', [])
+    return messages
+
+
+def get_message_detail(service, msg_id):
+    msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
+    payload = msg.get('payload', {})
+    headers = payload.get('headers', [])
+    subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
+    date_str = next((h['value'] for h in headers if h['name'] == 'Date'), '')
+    date = pd.to_datetime(date_str)
+    parts = payload.get('parts', [])
+    body = ''
+    if parts:
+        for part in parts:
+            if part.get('mimeType') == 'text/plain':
+                data = part['body']['data']
+                body = base64.urlsafe_b64decode(data).decode('utf-8')
+                break
+    else:
+        data = payload.get('body', {}).get('data')
+        if data:
+            body = base64.urlsafe_b64decode(data).decode('utf-8')
+    return subject, body, date
+
+
+def extract_job_info(subject, body):
+    text = subject + '\n' + body
+    if not any(k.lower() in text.lower() for k in JOB_KEYWORDS):
+        return None
+    match = JOB_APP_PATTERN.search(text)
+    app_code = match.group(1) if match else ''
+    # Very naive extraction heuristics
+    job_title_match = re.search(r"for\s+(?:the\s+)?(.*)\s+position", text, re.IGNORECASE)
+    job_title = job_title_match.group(1) if job_title_match else ''
+    company_match = re.search(r"at\s+([A-Za-z0-9 &]+)", text)
+    company = company_match.group(1).strip() if company_match else ''
+    return app_code, job_title, company
+
+
+def scan_job_applications():
+    service = authenticate()
+    messages = query_messages(service)
+    rows = []
+    for m in messages:
+        subject, body, date = get_message_detail(service, m['id'])
+        info = extract_job_info(subject, body)
+        if info:
+            app_code, job_title, company = info
+            rows.append({
+                'application_code': app_code,
+                'date': date.strftime('%Y-%m-%d'),
+                'company': company,
+                'job_title': job_title,
+            })
+    df = pd.DataFrame(rows)
+    print(df)
+    if not df.empty:
+        df.to_csv('job_applications.csv', index=False)
+        print('Saved to job_applications.csv')
+
+def main():
+    scan_job_applications()
+
+
+if __name__ == '__main__':
+    main()
 
EOF
)

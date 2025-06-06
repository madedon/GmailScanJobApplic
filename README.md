# GmailScanJobApplic

This repository contains a simple Python script for scanning a Gmail
mailbox and extracting basic information about job applications from
your inbox. By default it searches the last six months of messages. The
script uses the Gmail API and stores the results in a CSV file.

## Setup
Make sure you have Python 3.8+ installed.

1. Create a Google Cloud project and enable the Gmail API.
2. Download the `credentials.json` file for an OAuth client and place it
   in the repository root (this file is ignored by Git). The script will
   fail if this file is not present.
3. Install the required packages:

```bash
pip install -r requirements.txt
```

4. Run the script (use ``--months`` to change the search window):

```bash
python scan_job_applications.py --months 6
```

The first run will open a browser window to authorize Gmail access and
create a `token.json` file. The script outputs a table of job
applications and saves the result to `job_applications.csv`.

## Notes

The extraction logic is very naive. It searches for keywords like
"job", "application", and "career" and tries to pull an application code,
company name, and job title from the email contents. Replies from
addresses that contain ``MyWorkday`` are also treated as job application
responses. You may need to
adjust the regular expressions in `scan_job_applications.py` to match
your specific email format.
Use the ``--months`` option to adjust how far back the search goes.

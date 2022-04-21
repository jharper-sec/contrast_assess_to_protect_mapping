# Introduction
Maps Assess Vulnerabilities to Protect Rules and Generates Corresponding CSV Files

# Prerequisites
* Python 3.x

# Quick Start
1. Install Dependencies
```bash
pip3 install -r requirements.txt
```

2. Configure Credentials
Edit the `contrast_security.yaml` file, replacing the below values with your credentials from: `Contrast UI -> User Settings -> YOUR KEYS`
```yaml
api:
  url: CONTRAST_URL
  api_key: CONTRAST_API_KEY
  service_key: CONTRAST_SERVICE_KEY
  user_name: CONTRAST_USER_NAME
  organization_id: CONTRAST_ORGANIZATION_ID
```

3. Run
Enter the following command to run
```bash
python3 main.py
```

4. Two CSV files will be generated
* `protect_vulnerability_mapping.csv`
* `protection_statuses.csv`

# Troubleshooting
Logging is not very robust yet, but there should be some information within the `contrast.log` file if you run into issues.
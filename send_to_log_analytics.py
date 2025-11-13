#send_to_log_analytics.py
import json
import hashlib
import hmac
import base64
import datetime
import requests
import os
from dotenv import load_dotenv
import time

# Load values from .env file
load_dotenv()

WORKSPACE_ID = os.getenv("LOG_ANALYTICS_WORKSPACE_ID")
SHARED_KEY = os.getenv("LOG_ANALYTICS_SHARED_KEY")
LOG_TYPE = os.getenv("LOG_ANALYTICS_CUSTOM_LOG_NAME")

# Function to build the authentication signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, hashlib.sha256).digest()
    ).decode()
    return f"SharedKey {customer_id}:{encoded_hash}"

# Function to post logs to Log Analytics
def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)

    uri = f"https://{customer_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri, data=body, headers=headers)
    print(f"Response code: {response.status_code}")
    if response.status_code not in (200, 202):
        print(f"Error: {response.text}")

# Main script
if __name__ == "__main__":
    try:
        # Read your fake log records
        with open("fake_logs.json", "r") as f:
            data = json.load(f)

        print(f"Loaded {len(data)} records from fake_logs.json")

        # Send logs in batches of 100
        batch_size = 100
        for i in range(0, len(data), batch_size):
            batch = data[i:i+batch_size]
            body = json.dumps(batch)
            post_data(WORKSPACE_ID, SHARED_KEY, body, LOG_TYPE)
            print(f" Sent {i + len(batch)} of {len(data)} records\n")
            time.sleep(1)  # avoid throttling

        print(" All logs sent successfully!")

    except Exception as e:
        print(" Error sending logs:", e)
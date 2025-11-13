#fake_data.py
import json
import random
import base64
import hmac
import hashlib
import requests
import logging
import os
from datetime import datetime, timedelta, timezone
from faker import Faker
from azure.storage.blob import BlobServiceClient
from dotenv import load_dotenv

# --- Load environment variables ---
load_dotenv()

# --- Logging setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# --- Configuration from .env ---
LOG_ANALYTICS_WORKSPACE_ID = os.getenv("LOG_ANALYTICS_WORKSPACE_ID")
LOG_ANALYTICS_SHARED_KEY = os.getenv("LOG_ANALYTICS_SHARED_KEY")
LOG_TYPE = os.getenv("LOG_TYPE", "TelemetryLogs")

BLOB_CONNECTION_STRING = os.getenv("BLOB_CONNECTION_STRING")
STORAGE_CONTAINER_NAME = os.getenv("STORAGE_CONTAINER_NAME", "logs")

NUM_RECORDS = 1000
OUTPUT_FILENAME = "fake_logs.json"

# --- Faker setup ---
fake = Faker()

SERVICE_NAMES = ["payments-api", "user-service", "inventory-mgmt", "notification-worker", "auth-gateway"]
LEVELS = [("error", 0.10), ("warn", 0.20), ("info", 0.70)]
REGIONS = ["eastus", "westus2", "centralus", "westeurope"]
ENVIRONMENTS = ["prod", "staging", "dev"]
RELEASES = [f"v1.{i}.{j}" for i in range(1, 4) for j in range(0, 5)]

ERROR_MESSAGES = [
    "Database timeout executing query SELECT ...",
    "Authentication failure for user 'guest'",
    "HTTP 500: Internal Server Error on dependency call to 'inventory-mgmt'",
    "ResourceNotAvailableException: Queue 'order-processing' is full.",
    "Configuration drift detected: 'feature_flag_x' is unexpectedly OFF.",
    "Critical: Failed to establish connection to Azure Key Vault.",
]
OTHER_MESSAGES = [
    "High latency detected on GET /api/v1/orders",
    "Processing request /api/v1/payments. Success.",
    "User session expired, re-authentication required.",
    "Worker thread started successfully.",
    "Telemetry flushed successfully to Application Insights.",
    "Dependency call to external service returned 204 No Content.",
]


# --- Helper Functions ---
def get_weighted_random(choices_weights):
    choices, weights = zip(*choices_weights)
    return random.choices(choices, weights=weights, k=1)[0]


def generate_telemetry_data(num_records):
    telemetry_data = []
    current_time = datetime.now(timezone.utc) - timedelta(hours=1)

    for i in range(num_records):
        current_time += timedelta(seconds=random.randint(2, 15), milliseconds=random.randint(0, 999))
        service = random.choice(SERVICE_NAMES)
        level = get_weighted_random(LEVELS)
        region = random.choice(REGIONS)
        env = random.choice(ENVIRONMENTS)
        release = random.choice(RELEASES)

        record = {
            "timestamp": current_time.isoformat(timespec='milliseconds'),
            "service": service,
            "instance": f"{service.split('-')[0]}-v{random.randint(1, 3)}-{random.randint(1, 20)}",
            "level": level,
            "correlation_id": fake.uuid4(),
            "region": region,
            "tags": {"env": env, "release": release}
        }

        if level == "error":
            record["message"] = f"ERR_ID_{i:04d}: {random.choice(ERROR_MESSAGES)}"
            record["latency_ms"] = random.randint(1000, 4500)
        elif level == "warn":
            record["message"] = f"WARN_ID_{i:04d}: {random.choice(OTHER_MESSAGES)}"
            record["latency_ms"] = random.randint(300, 1000)
        else:
            record["message"] = f"INFO_ID_{i:04d}: {random.choice(OTHER_MESSAGES)}"
            record["latency_ms"] = random.randint(50, 300)

        telemetry_data.append(record)
    return telemetry_data


def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
    return f"SharedKey {customer_id}:{encoded_hash}"


def post_to_log_analytics(customer_id, shared_key, body, log_type):
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    rfc1123_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123_date, content_length, method, content_type, resource)
    uri = f"https://{customer_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"

    headers = {
        "Content-Type": content_type,
        "Authorization": signature,
        "Log-Type": log_type,
        "x-ms-date": rfc1123_date,
    }

    response = requests.post(uri, data=body, headers=headers)
    if 200 <= response.status_code < 300:
        logging.info(f" Successfully uploaded {len(json.loads(body))} records to Log Analytics (Shared Key).")
    else:
        logging.error(f" Failed to send data: {response.status_code} - {response.text}")


def upload_to_blob_storage(file_path, connection_string, container_name):
    try:
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        container_client = blob_service_client.get_container_client(container_name)

        # Create container if it doesn’t exist
        try:
            container_client.create_container()
        except Exception:
            pass

        blob_name = f"telemetry/{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{os.path.basename(file_path)}"
        blob_client = container_client.get_blob_client(blob_name)
        with open(file_path, "rb") as data:
            blob_client.upload_blob(data, overwrite=True)

        logging.info(f" File uploaded to Azure Blob Storage: {blob_name}")
    except Exception as e:
        logging.error(f" Error uploading to Blob Storage: {e}")


# --- Main Process ---
if __name__ == "__main__":
    logging.info(f"Starting generation and upload process for {NUM_RECORDS} records...")

    logs = generate_telemetry_data(NUM_RECORDS)
    with open(OUTPUT_FILENAME, "w") as f:
        json.dump(logs, f, indent=2)
    logging.info(f"Generated {len(logs)} records → saved to {OUTPUT_FILENAME}")

    try:
        post_to_log_analytics(
            LOG_ANALYTICS_WORKSPACE_ID,
            LOG_ANALYTICS_SHARED_KEY,
            json.dumps(logs),
            LOG_TYPE
        )
    except Exception as e:
        logging.error(f"Error sending logs to Log Analytics: {e}")

    if BLOB_CONNECTION_STRING:
        upload_to_blob_storage(OUTPUT_FILENAME, BLOB_CONNECTION_STRING, STORAGE_CONTAINER_NAME)
    else:
        logging.error("Blob Storage connection string missing in .env. Skipping archive.")

    logging.info("Process finished.")
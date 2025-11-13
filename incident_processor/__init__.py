import azure.functions as func
import json
import os
import logging
import requests
from datetime import datetime, timezone
from azure.cosmos import CosmosClient, PartitionKey

COSMOS_URI = os.getenv("COSMOS_URI")
COSMOS_KEY = os.getenv("COSMOS_KEY")
COSMOS_DB_NAME = os.getenv("COSMOS_DB_NAME", "incidents")
COSMOS_CONTAINER_NAME = os.getenv("COSMOS_CONTAINER_NAME", "incidents")
LOGIC_APP_URL = os.getenv("LOGIC_APP_URL")

try:
    cosmos_client = CosmosClient(COSMOS_URI, COSMOS_KEY)
    database = cosmos_client.create_database_if_not_exists(id=COSMOS_DB_NAME)
    container = database.create_container_if_not_exists(
        id=COSMOS_CONTAINER_NAME,
        partition_key=PartitionKey(path="/service"),
        offer_throughput=400
    )
    logging.info("Connected to Cosmos DB successfully.")
except Exception as e:
    logging.error(f"Failed to initialize Cosmos DB client: {e}")
    container = None


def main(msg: func.ServiceBusMessage):
    logging.info("ServiceBus trigger fired - processing telemetry.")
    try:
        body = msg.get_body().decode("utf-8")
        telemetry = json.loads(body)
        logging.info(f"Received telemetry message: {telemetry}")

        level = telemetry.get("level", "").lower()
        latency = telemetry.get("latency_ms", 0)

        if level == "error":
            severity = "P1"
        elif level == "warn" or latency > 1000:
            severity = "P2"
        else:
            severity = "P3"

        incident_id = f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        created_time = datetime.now(timezone.utc).isoformat()

        incident_doc = {
            "id": incident_id,
            "created_at": created_time,
            "severity": severity,
            "service": telemetry.get("service", "unknown"),
            "services_affected": [telemetry.get("service", "unknown")],
            "summary": telemetry.get("message", "No summary provided."),
            "correlation_ids": [telemetry.get("correlation_id")] if telemetry.get("correlation_id") else [],
            "correlated_logs": [
                {
                    "timestamp": telemetry.get("timestamp"),
                    "instance": telemetry.get("instance"),
                    "message": telemetry.get("message"),
                    "level": telemetry.get("level"),
                    "latency_ms": telemetry.get("latency_ms"),
                    "region": telemetry.get("region"),
                    "tags": telemetry.get("tags", {})
                }
            ],
            "root_cause_hints": _generate_root_cause_hints(telemetry),
            "remediation_suggestions": _generate_remediation_suggestions(telemetry),
            "status": "open",
            "remediation_runs": []
        }

        if container:
            container.upsert_item(incident_doc)
            logging.info(f"Incident stored successfully in Cosmos DB: {incident_id}")
        else:
            logging.error("Cosmos DB container not initialized. Skipping insert.")

        if LOGIC_APP_URL:
            payload = {
                "incident_id": incident_id,
                "severity": incident_doc["severity"],
                "summary": incident_doc["summary"],
                "services_affected": incident_doc["services_affected"],
                "timestamp": created_time
            }
            try:
                response = requests.post(LOGIC_APP_URL, json=payload)
                if response.status_code in [200, 202]:
                    logging.info(f"Logic App triggered successfully for {incident_id}")
                else:
                    logging.warning(f"Logic App trigger failed ({response.status_code}): {response.text}")
            except Exception as e:
                logging.error(f"Error while triggering Logic App: {e}")
        else:
            logging.warning("LOGIC_APP_REMEDIATE_URL not configured, skipping Logic App trigger.")

        logging.info(f"Finished processing incident: {incident_id}")

    except Exception as e:
        logging.error(f"Error processing Service Bus message: {e}")


def _generate_root_cause_hints(telemetry):
    hints = []
    msg = telemetry.get("message", "").lower()
    if "timeout" in msg:
        hints.append({"hint": "Possible database or network latency", "confidence": 0.9})
    if "connection" in msg:
        hints.append({"hint": "Connection failure to backend service", "confidence": 0.8})
    if "cpu" in msg or "memory" in msg:
        hints.append({"hint": "High resource utilization", "confidence": 0.75})
    if not hints:
        hints.append({"hint": "Investigate logs for anomalies", "confidence": 0.5})
    return hints


def _generate_remediation_suggestions(telemetry):
    msg = telemetry.get("message", "").lower()
    suggestions = []
    if "database" in msg or "query" in msg:
        suggestions.append({"action": "scale-database-instance", "automatic": False})
    if "service" in msg or "timeout" in msg:
        suggestions.append({"action": "restart-service", "automatic": False})
    if not suggestions:
        suggestions.append({"action": "notify-oncall-engineer", "automatic": False})
    return suggestions

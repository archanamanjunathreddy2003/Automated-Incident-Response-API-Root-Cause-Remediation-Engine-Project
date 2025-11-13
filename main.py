# api/main.py
import os
import json
import logging
import datetime
import numpy as np
import requests
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Body, Query
from pydantic import BaseModel
from azure.cosmos import CosmosClient, exceptions as cosmos_exceptions
from azure.servicebus import ServiceBusClient, ServiceBusMessage
from sentence_transformers import SentenceTransformer
from opencensus.ext.azure.log_exporter import AzureLogHandler

# ---------------------------------------------------------------------
# Load settings (local.settings.json expected at project root)
# ---------------------------------------------------------------------
def load_local_settings():
    if not os.path.exists("local.settings.json"):
        return {}
    with open("local.settings.json") as f:
        return json.load(f).get("Values", {})

SETTINGS = load_local_settings()

# ---------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------
logger = logging.getLogger("air-api")
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(console_handler)

if SETTINGS.get("APPLICATIONINSIGHTS_CONNECTION_STRING"):
    try:
        ai_handler = AzureLogHandler(connection_string=SETTINGS["APPLICATIONINSIGHTS_CONNECTION_STRING"])
        ai_handler.setLevel(logging.INFO)
        logger.addHandler(ai_handler)
        logger.info("Application Insights logging enabled")
    except Exception:
        logger.exception("Failed to initialize Application Insights handler")

logging.getLogger("uamqp").setLevel(logging.WARNING)
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)

# ---------------------------------------------------------------------
# Environment variables
# ---------------------------------------------------------------------
SERVICEBUS_CONN = SETTINGS.get("SERVICEBUS_CONN") or os.getenv("SERVICEBUS_CONN")
SERVICEBUS_QUEUE = SETTINGS.get("SERVICEBUS_QUEUE") or os.getenv("SERVICEBUS_QUEUE", "incident-queue")

COSMOS_URI = SETTINGS.get("COSMOS_URI") or os.getenv("COSMOS_URI")
COSMOS_KEY = SETTINGS.get("COSMOS_KEY") or os.getenv("COSMOS_KEY")
COSMOS_DB = SETTINGS.get("COSMOS_DB_NAME") or os.getenv("COSMOS_DB", "incidentdb")
COSMOS_CONTAINER = SETTINGS.get("COSMOS_CONTAINER_NAME") or os.getenv("COSMOS_CONTAINER", "incidents")
VECTOR_CONTAINER = SETTINGS.get("VECTOR_CONTAINER") or os.getenv("VECTOR_CONTAINER", "vector_db")

LOGIC_APP_URL = SETTINGS.get("LOGIC_APP_URL") or os.getenv("LOGIC_APP_URL")

# ---------------------------------------------------------------------
# Validate required settings (log warnings; fail when used)
# ---------------------------------------------------------------------
if not COSMOS_URI or not COSMOS_KEY:
    logger.warning("COSMOS_URI or COSMOS_KEY not set. Cosmos operations will fail until configured.")

# ---------------------------------------------------------------------
# Cosmos DB + Service Bus setup
# ---------------------------------------------------------------------
_cosmos_client = None
_cosmos_db = None
_cosmos_container = None
_vector_container = None
try:
    if COSMOS_URI and COSMOS_KEY:
        _cosmos_client = CosmosClient(COSMOS_URI, credential=COSMOS_KEY)
        _cosmos_db = _cosmos_client.get_database_client(COSMOS_DB)
        _cosmos_container = _cosmos_db.get_container_client(COSMOS_CONTAINER)
        # vector container (for embeddings) - may be same or different container
        try:
            _vector_container = _cosmos_db.get_container_client(VECTOR_CONTAINER)
        except Exception:
            _vector_container = _cosmos_container
        logger.info(f"Connected to Cosmos DB: {COSMOS_DB} / container: {COSMOS_CONTAINER}")
except Exception:
    logger.exception("Failed to initialize Cosmos client")

_servicebus_client = None
def get_servicebus_client():
    global _servicebus_client
    if _servicebus_client is None:
        if not SERVICEBUS_CONN:
            raise RuntimeError("SERVICEBUS_CONN not configured")
        _servicebus_client = ServiceBusClient.from_connection_string(SERVICEBUS_CONN)
        logger.info("Initialized persistent Service Bus client")
    return _servicebus_client

# ---------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------
app = FastAPI(title="Automated Incident Response API", version="6.2", description="Incident automation with Logic App integration")

# ---------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------
class Telemetry(BaseModel):
    timestamp: str
    service: str
    instance: Optional[str] = None
    level: str
    message: str
    correlation_id: Optional[str] = None
    latency_ms: Optional[int] = None
    region: Optional[str] = None
    tags: Optional[dict] = {}

class RemediateRequest(BaseModel):
    action: str
    initiated_by: Optional[str] = "api_user"
    comment: Optional[str] = None

class SearchRequest(BaseModel):
    q: str
    top_k: Optional[int] = 5

class CosmosAlertRequest(BaseModel):
    service: str
    severity: str

# ---------------------------------------------------------------------
# Helper functions: embedding model + similarity
# ---------------------------------------------------------------------
_model = None
def get_embedding_model():
    global _model
    if _model is None:
        logger.info("Loading embedding model...")
        _model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    return _model

def cosine_similarity(a: np.ndarray, b: np.ndarray):
    if a is None or b is None:
        return 0.0
    if np.linalg.norm(a) == 0 or np.linalg.norm(b) == 0:
        return 0.0
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

# ---------------------------------------------------------------------
# Endpoint implementations
# ---------------------------------------------------------------------
@app.post("/simulate", status_code=200)
def simulate_incident(telemetry: Telemetry):
    """
    Create a synthetic incident document (stored in Cosmos) and push the same
    document to the Service Bus queue for end-to-end testing.
    """
    try:
        now = now_iso()
        incident_id = f"INC-{now.replace(':','').replace('-','')}"
        # severity heuristics
        severity = "P3"
        if telemetry.level and telemetry.level.lower() == "error":
            severity = "P1"
        elif telemetry.latency_ms and telemetry.latency_ms > 1000:
            severity = "P2"

        incident_doc = {
            "id": incident_id,
            "created_at": now,
            "timestamp": telemetry.timestamp,
            "service": telemetry.service,
            "instance": telemetry.instance,
            "level": telemetry.level,
            "message": telemetry.message,
            "summary": telemetry.message[:1000],
            "correlation_id": telemetry.correlation_id,
            "latency_ms": telemetry.latency_ms,
            "region": telemetry.region,
            "tags": telemetry.tags or {},
            "severity": severity,
            "status": "new",
            "source": "simulate_api",
            "correlated_logs": [],
            "root_cause_hints": [],
            "remediation_suggestions": [],
            "remediation_runs": []
        }

        # store to cosmos
        if _cosmos_container:
            _cosmos_container.upsert_item(incident_doc)
            logger.info("Stored simulated incident in Cosmos %s", incident_id)
        else:
            logger.warning("Cosmos container not configured; skipping store")

        # push to service bus for pipeline testing
        sb = get_servicebus_client()
        with sb.get_queue_sender(SERVICEBUS_QUEUE) as sender:
            sender.send_messages(ServiceBusMessage(json.dumps(incident_doc)))
        logger.info("Published simulated incident to Service Bus queue %s", SERVICEBUS_QUEUE)

        return {"status": "queued_and_stored", "incident_id": incident_id}
    except Exception as e:
        logger.exception("simulate_incident failed")
        raise HTTPException(status_code=500, detail=f"Simulation failed: {e}")

@app.get("/incidents")
def list_incidents(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=200), service: Optional[str] = Query(None)):
    """
    Paginated list of incidents. Uses client-side paging (fetches ordered items and slices).
    Returns total_count and items for the requested page.
    """
    try:
        if not _cosmos_container:
            raise HTTPException(status_code=500, detail="Cosmos DB not configured")

        base_query = "SELECT * FROM c"
        params = None
        if service:
            base_query += " WHERE c.service = @service"
            params = [{"name":"@service","value":service}]
        base_query += " ORDER BY c.created_at DESC"

        items = list(_cosmos_container.query_items(query=base_query, parameters=params, enable_cross_partition_query=True))
        total = len(items)
        start = (page - 1) * page_size
        end = start + page_size
        page_items = items[start:end]
        return {"page": page, "page_size": page_size, "total": total, "items": page_items}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("list_incidents failed")
        raise HTTPException(status_code=500, detail=f"Failed to query incidents: {e}")

@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    """
    Return full incident document including correlated_logs.
    """
    try:
        if not _cosmos_container:
            raise HTTPException(status_code=500, detail="Cosmos DB not configured")

        query = "SELECT * FROM c WHERE c.id = @id"
        params = [{"name":"@id", "value":incident_id}]
        results = list(_cosmos_container.query_items(query=query, parameters=params, enable_cross_partition_query=True))
        if not results:
            raise HTTPException(status_code=404, detail="Incident not found")
        return results[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("get_incident failed")
        raise HTTPException(status_code=500, detail=f"Error fetching incident: {e}")

@app.post("/incidents/{incident_id}/remediate")
def remediate_incident(incident_id: str, body: RemediateRequest):
    """
    Trigger Logic App remediation workflow for a specific incident.
    Pulls remediation suggestions from Cosmos DB, triggers Logic App, and logs the run.
    """
    if not LOGIC_APP_URL:
        raise HTTPException(status_code=500, detail="Logic App URL not configured")

    try:
        #  Fetch incident from Cosmos DB
        query = "SELECT * FROM c WHERE c.id = @id"
        params = [{"name": "@id", "value": incident_id}]
        results = list(_cosmos_container.query_items(
            query=query, parameters=params, enable_cross_partition_query=True
        ))

        if not results:
            raise HTTPException(status_code=404, detail="Incident not found")

        incident = results[0]

        #  Pick remediation suggestion from Cosmos DB
        suggestions = incident.get("remediation_suggestions", [])
        if not suggestions:
            raise HTTPException(status_code=404, detail="No remediation suggestions found for this incident")

        suggestion = suggestions[0]
        action = suggestion.get("action", "manual review required")
        automatic = suggestion.get("automatic", False)

        #  Construct payload for Logic App
        payload = {
            "incident_id": incident_id,
            "service": incident.get("service"),
            "severity": incident.get("severity"),
            "summary": incident.get("summary"),
            "action": action,
            "automatic": automatic,
            "initiated_by": body.initiated_by or "api_user",
            "comment": body.comment or "Triggered via API",
            "started_at": datetime.datetime.utcnow().isoformat() + "Z",
        }

        logger.info(f"Sending payload to Logic App: {json.dumps(payload, indent=2)}")

        #  Call Logic App webhook
        resp = requests.post(
            LOGIC_APP_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30
        )

        #  Handle response cleanly
        if resp.status_code not in (200, 202):
            logger.error(f"Logic App returned {resp.status_code}: {resp.text}")
            raise HTTPException(status_code=502, detail=f"Logic App returned {resp.status_code}: {resp.text}")

        #  Create remediation run record
        remediation_run = {
            "started_at": payload["started_at"],
            "action": action,
            "initiated_by": payload["initiated_by"],
            "comment": payload["comment"],
            "logic_app_status": resp.status_code,
            "logic_app_message": "Triggered successfully",
        }

        #  Update Cosmos DB
        incident.setdefault("remediation_runs", []).append(remediation_run)
        _cosmos_container.upsert_item(incident)

        logger.info(f"Remediation run recorded for {incident_id}")

        #  Return clean response
        return {
            "status": "logic_app_notified",
            "incident_id": incident_id,
            "remediation_runs": [remediation_run],
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("remediate_incident failed")
        raise HTTPException(status_code=500, detail=f"Remediation failed: {repr(e)}")



@app.post("/search")
def semantic_search(req: SearchRequest):
    """
    Semantic search over vector container stored in Cosmos. Returns top-k by cosine similarity.
    """
    try:
        if not _vector_container:
            raise HTTPException(status_code=500, detail="Vector container not configured")

        model = get_embedding_model()
        query_emb = model.encode([req.q], convert_to_numpy=True)[0]
        # fetch all vector docs (for small demo sets). For production use a real vector DB or proper filtering.
        query = "SELECT c.id, c.vector_id, c.summary, c.embedding, c.service, c.severity FROM c"
        docs = list(_vector_container.query_items(query=query, enable_cross_partition_query=True))
        results = []
        for d in docs:
            emb = np.array(d.get("embedding", []), dtype=float)
            score = cosine_similarity(query_emb, emb)
            results.append({
                "vector_id": d.get("vector_id", d.get("id")),
                "summary": d.get("summary", ""),
                "service": d.get("service"),
                "severity": d.get("severity"),
                "score": round(score, 6)
            })
        results.sort(key=lambda x: x["score"], reverse=True)
        return {"count": len(results), "results": results[: req.top_k or 5]}
    except Exception as e:
        logger.exception("semantic_search failed")
        raise HTTPException(status_code=500, detail=f"Semantic search failed: {e}")



@app.get("/")
def health():
    return {"status": "ok", "version": "6.2"}

# cleanup
@app.on_event("shutdown")
def app_shutdown():
    global _servicebus_client
    try:
        if _servicebus_client:
            _servicebus_client.close()
            logger.info("Closed Service Bus client")
    except Exception:
        logger.exception("Error closing ServiceBus client")

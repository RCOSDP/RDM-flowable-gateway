# RDM-flowable-gateway

Gateway service bridging GakuNin RDM and Flowable workflow engine. Flowable's open-source REST API supports only Basic authentication; this gateway accepts JWT-authenticated requests from RDM and securely proxies workflow access to GakuNin RDM APIs without exposing delegation tokens to Flowable.

## Getting started

1. Copy `.env.sample` to `.env` and adjust the credentials that bootstrap Flowable REST. Set either `RDM_KEYSET_PATH` (local JSON file) or `RDM_KEYSET_URL` (RDM endpoint) so the gateway can load the RDM service's public keys used to sign workflow tokens. Configure `GATEWAY_SIGNING_KEY_ID`, `GATEWAY_SIGNING_PRIVATE_KEY_PATH`, `DATABASE_URL`, and `ENCRYPTION_KEY` so the gateway can connect to PostgreSQL, sign outbound tokens, and encrypt stored delegation tokens. Define `RDM_ALLOWED_DOMAINS`, `RDM_ALLOWED_API_DOMAINS`, and `RDM_ALLOWED_WATERBUTLER_URLS` with comma-separated `scheme://host[:port]` entries limiting which upstream hosts the delegation proxy will contact.
2. For local testing, copy `config/keyset.example.json` to `config/keyset.json` and replace the sample key with the PEM-encoded RDM public key (asymmetric algorithms only: RS*/ES*). In integrated environments prefer `RDM_KEYSET_URL` pointing at `/api/v1/workflow/keyset/` on the RDM backend.
3. Copy `config/gateway-dev-v1.key.example` to `config/gateway-dev-v1.key` (or supply your own private key) so the gateway can sign requests back to RDM.
4. Build and start the stack:
   ```bash
   docker compose up --build
   ```
5. Flowable REST will be exposed on `http://127.0.0.1:8090/flowable-rest/`. The gateway FastAPI stub listens on `http://127.0.0.1:8088/`.

Both services share the same network, so the gateway can reach Flowable at the internal URL defined by `FLOWABLE_REST_BASE_URL` (defaults to `http://flowable:8080/flowable-rest`).

Stop the stack with `docker compose down` when you are done.

## Authentication

Every gateway endpoint except `/healthz` expects an `Authorization: Bearer <token>` header. The token must be signed with a key whose `kid` is present in the keyset and satisfy any optional issuer/audience/claim constraints configured via environment variables. Operations that modify Flowable state require the scope `workflow::delegate`.

### Signing tokens for RDM

The gateway signs tokens with its own key pair before calling the RDM backend. Register the corresponding public key with RDM (see `/api/v1/workflow/engine-keys/`). With the environment variables above in place you can issue a token via the helper:

```bash
python - <<'PYTHON'
import datetime as dt
from gateway.signing import issue_gateway_token

payload = {
    "sub": "gateway-dev",
    "scope": "workflow::delegate",
    "iat": dt.datetime.utcnow(),
    "exp": dt.datetime.utcnow() + dt.timedelta(minutes=5),
}

token = issue_gateway_token(payload)
print(token)
PYTHON
```

### Minting a development token

```bash
python - <<'PYTHON'
import datetime as dt
import jwt

private_key_path = "/path/to/rdm-service.key"  # RDM service private key used for local signing
with open(private_key_path, "r", encoding="utf-8") as fh:
    private_key = fh.read()

payload = {
    "sub": "local-dev",
    "scope": "gateway:read",
    "iat": dt.datetime.utcnow(),
    "exp": dt.datetime.utcnow() + dt.timedelta(minutes=5),
}
headers = {"kid": "rdm-service-v1"}
print(jwt.encode(payload, private_key, algorithm="RS256", headers=headers))
PYTHON
```

Use the printed token when calling e.g. `GET http://127.0.0.1:8088/config`. The matching public key must appear in `config/keyset.json` (or be published by the RDM backend for the same `kid`).

### Publishing the gateway keyset

The gateway exposes `GET /keyset`, which returns the PEM for its configured signing key inside a JWKS-like document. Ensure `.env` sets `GATEWAY_SIGNING_KEY_ID` and that `config/gateway-dev-v1.key` (or your chosen file) holds a valid RSA/EC private key before starting the stack. With the containers up you can inspect the payload:

```bash
docker compose up -d
curl -s http://127.0.0.1:8088/keyset | python -m json.tool
docker compose down
```

Supply this JSON to RDM when registering the engine to avoid copying PEM material manually.

## Flowable operations

Authenticated requests can proxy a small subset of Flowable's REST API. The gateway signs into Flowable with `FLOWABLE_REST_APP_ADMIN_USER_ID` / `FLOWABLE_REST_APP_ADMIN_PASSWORD`.

- `GET /flowable/process-definitions`: returns Flowable's `service/repository/process-definitions` payload (query parameters are forwarded verbatim).
- `GET /flowable/process-instances`: proxies `service/runtime/process-instances`.
- `POST /flowable/process-instances`: starts a process instance. Body mirrors Flowable's request schema:
  ```json
  {
    "processDefinitionId": "test:1:25",
    "name": "example",
    "businessKey": "rdm:node:abc123",
    "variables": [
      {"name": "key", "value": "value", "type": "string"}
    ]
  }
  ```
- `GET /flowable/tasks`: proxies `service/runtime/tasks`. Supplying `businessKey` filters tasks to process instances with that key.
- `GET /flowable/history/historic-process-instances/{instance_id}`: proxies Flowable history lookups for a specific process instance.
- `POST /flowable/tasks/{task_id}`: forwards task operations (default `{"action": "complete"}` mirrors Flowable).

Example start and complete cycle:

```bash
TOKEN="$(python - <<'PY'
import datetime as dt, jwt
with open('config/rdm-service.key') as fh:
    key = fh.read()
now = dt.datetime.utcnow()
print(jwt.encode(
    {
        'sub': 'gateway-dev',
        'scope': 'workflow::delegate',
        'iat': now,
        'exp': now + dt.timedelta(minutes=5),
    },
    key,
    algorithm='RS256',
    headers={'kid': 'rdm-service-v1'},
))
PY)"

curl -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"processDefinitionId": "example:1:1001", "businessKey": "rdm:node:abc123"}' \
     http://127.0.0.1:8088/flowable/process-instances

curl -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8088/flowable/tasks?businessKey=rdm:node:abc123"

curl -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"variables": [{"name": "approval", "value": true}]}' \
  http://127.0.0.1:8088/flowable/tasks/<task-id>
```

## Deploying the publication workflow

`config/rdm-publication-approval.bpmn20.xml` embeds the reviewer form as `flowable:formProperty` entries on the `reviewTask`. Flowable therefore exposes the same information through `service/form/form-data`, which the gateway translates into the field payload Ember expects.

Deploy the definition with the CLI helper:

```bash
python3 cli/deploy_workflow.py \
    --asset RDM-flowable-gateway/config/rdm-publication-approval.bpmn20.xml
```

Environment defaults mirror the Docker stack. Override `--flowable-url`, `--username`, or `--password` to target a different Flowable instance. The script requires the `httpx` package; install the gateway requirements locally with `pip install -r RDM-flowable-gateway/requirements.txt` before running the command. Successful execution prints the deployment id and registered resources.

## Delegation Token Proxy

The gateway provides a secure proxy mechanism for Flowable workflows to access RDM APIs without exposing actual tokens.

### Setup

1. **Generate Encryption Key**:
   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

2. **Update your `.env` file**:
   Set `ENCRYPTION_KEY` to the value you generated in the previous step so the gateway can decrypt stored delegation tokens.

3. **Initialize Database**:
   ```bash
   docker compose run gateway python -m gateway.init_db
   ```

### How It Works

1. **Token Storage**: When RDM starts a workflow process, it sends delegation tokens to the gateway in the `delegationTokens` field. The gateway encrypts and stores these tokens in PostgreSQL.

2. **Proxy URL Generation**: The gateway generates proxy URLs and adds them as Flowable process variables:
   - `RDM_CREATOR_API_URL` → `http://gateway:8088/rdm/{process_instance_id}/creator/api`
   - `RDM_CREATOR_WEB_URL` → `http://gateway:8088/rdm/{process_instance_id}/creator/web`
   - `RDM_CREATOR_WATERBUTLER_URL` → `http://gateway:8088/rdm/{process_instance_id}/creator/waterbutler`

3. **Workflow Access**: Flowable workflows use these proxy URLs to access RDM services. The gateway automatically retrieves the appropriate token, decrypts it, and forwards the request with the `Authorization` header.

### Example Workflow Usage

```xml
<serviceTask id="fetchNode" name="Fetch Node Data">
  <extensionElements>
    <flowable:field name="url">
      <flowable:expression>${RDM_CREATOR_API_URL}/v2/nodes/${RDM_NODE_ID}/</flowable:expression>
    </flowable:field>
  </extensionElements>
</serviceTask>
```

No `Authorization` header is needed; the gateway adds it automatically.

### Security Features

- **Encryption at Rest**: All token values are encrypted using Fernet before storage
- **Token Isolation**: Actual tokens never appear in Flowable variables or history
- **Role-Based Access**: Separate tokens for creator, manager, and executor roles
- **Strict Allowlist Enforcement**: Process variables `RDM_DOMAIN`, `RDM_API_DOMAIN`, and `RDM_WATERBUTLER_URL` are validated against `RDM_ALLOWED_DOMAINS`, `RDM_ALLOWED_API_DOMAINS`, and `RDM_ALLOWED_WATERBUTLER_URLS` respectively, preventing workflows from proxying tokens to untrusted hosts

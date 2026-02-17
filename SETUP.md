# OpenCTI MCP Setup Guide

This guide helps you connect the OpenCTI MCP to a threat intelligence platform.

---

## Prerequisites

**You need an OpenCTI instance.** This MCP connects to OpenCTI - it doesn't include one.

Options:
- **Use existing instance** - Your organization may already have OpenCTI
- **Deploy your own** - Run OpenCTI via Docker (see below)
- **Managed service** - Filigran (OpenCTI vendor) offers hosted options

---

## Option A: Connect to Existing Instance

If you already have OpenCTI running:

### Step 1: Get Your API Token

1. Log into your OpenCTI instance
2. Click your profile (top right) → **Profile**
3. Scroll to **API Access**
4. Copy your API token

### Step 2: Determine Your URL and Protocol

**Local Docker (same machine):** OpenCTI's Docker deployment serves HTTP on port 8080 by default. Traffic stays on localhost — HTTP is fine.
```
OPENCTI_URL=http://localhost:8080
```

**Remote server or cloud:** Use HTTPS. OpenCTI supports TLS natively (`APP__HTTPS_CERT__*`) or via a reverse proxy (Nginx, Caddy, Traefik).
```
OPENCTI_URL=https://opencti.example.com
```

**Self-signed certificates:** If your instance uses a self-signed cert, also set:
```
OPENCTI_SSL_VERIFY=false
```

### Step 3: Configure the MCP

Create a `.env` file:
- **Claude-IR install:** Create at `/path/to/claude-ir/.env`
- **Standalone install:** Create at `/path/to/opencti-mcp/.env`

```
OPENCTI_URL=https://your-opencti-instance.example.com
OPENCTI_TOKEN=your-api-token-here
```

Secure the file: `chmod 600 .env`

**Never paste tokens in chat.** Edit the file directly.

### Step 4: Verify Connection

```bash
cd opencti-mcp
source .venv/bin/activate
python -c "
from opencti_mcp.config import Config
from opencti_mcp.client import OpenCTIClient
config = Config.from_env()
client = OpenCTIClient(config)
result = client.validate_connection(skip_connectivity=False)
if result['valid']:
    ver = result.get('opencti_version', 'unknown')
    print(f'Connected to OpenCTI (version: {ver})')
else:
    for e in result.get('errors', []):
        print(f'ERROR: {e}')
for w in result.get('warnings', []):
    print(f'WARNING: {w}')
"
```

---

## Option B: Deploy Your Own OpenCTI

OpenCTI requires Docker and moderate system resources.

### Minimum Requirements

- **RAM:** 16GB minimum (32GB recommended)
- **CPU:** 4 cores minimum
- **Disk:** 50GB+ (grows with data)
- **Docker:** Docker Engine + Docker Compose

### Quick Deploy (Development/Testing)

```bash
# Clone OpenCTI Docker repo
git clone https://github.com/OpenCTI-Platform/docker.git opencti-docker
cd opencti-docker

# Copy sample environment
cp .env.sample .env

# Edit .env - set admin credentials and generate UUIDs
# OPENCTI_ADMIN_EMAIL=admin@example.com
# OPENCTI_ADMIN_PASSWORD=your-secure-password
# OPENCTI_ADMIN_TOKEN=$(uuidgen)  # Save this - it's your API token

# Start OpenCTI (first start takes several minutes)
docker-compose up -d
```

**First startup takes 5-15 minutes** as containers initialize.

Access at: `http://localhost:8080` (HTTP is the Docker default — fine for local dev/lab use).

**For remote access or production:** Put a reverse proxy (Nginx, Caddy) in front with TLS, or configure OpenCTI's native HTTPS via `APP__HTTPS_CERT__KEY` and `APP__HTTPS_CERT__CRT`. See [OpenCTI configuration docs](https://docs.opencti.io/latest/deployment/configuration/).

### Get Admin API Token

The token you set in `OPENCTI_ADMIN_TOKEN` in `.env` is your API token.

If you need to create additional tokens:
1. Log in as admin
2. Settings → Security → Users
3. Create user or edit existing
4. Copy API token from user profile

### Production Deployment

For production, see the official OpenCTI documentation:
- **Installation Guide:** https://docs.opencti.io/latest/deployment/installation/
- **Docker Deployment:** https://docs.opencti.io/latest/deployment/installation/#using-docker
- **Configuration:** https://docs.opencti.io/latest/deployment/configuration/

---

## Populating OpenCTI with Data

An empty OpenCTI isn't useful. You need threat intelligence feeds.

### Built-in Connectors

OpenCTI has connectors for many free feeds:
- **MITRE ATT&CK** - Techniques, groups, malware
- **CVE** - Vulnerability data
- **AlienVault OTX** - Community threat intel (free account)
- **Abuse.ch** - Malware, botnets, URLs
- **CISA KEV** - Known exploited vulnerabilities

Enable in: Settings → Connectors → Available Connectors

### Recommended Starting Connectors

1. **MITRE ATT&CK** - Essential for technique mapping
2. **CVE** - Vulnerability lookups
3. **CISA KEV** - Critical vulnerabilities
4. **AlienVault OTX** - Free community intel (requires free account)

### Connector Documentation

https://docs.opencti.io/latest/deployment/connectors/

---

## Configuration Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENCTI_URL` | Yes | `http://localhost:8080` | OpenCTI instance URL (use `https://` for remote) |
| `OPENCTI_TOKEN` | Yes | - | API token from OpenCTI |
| `OPENCTI_READ_ONLY` | No | `true` | Disable write operations |
| `OPENCTI_TIMEOUT` | No | `60` | Request timeout (seconds) |
| `OPENCTI_SSL_VERIFY` | No | `true` | Verify SSL certificates (set `false` for self-signed) |
| `OPENCTI_MAX_RESULTS` | No | `100` | Maximum results per query |
| `OPENCTI_MAX_RETRIES` | No | `3` | Retry attempts for failures |
| `OPENCTI_RETRY_DELAY` | No | `1.0` | Initial retry delay (seconds) |
| `OPENCTI_RETRY_MAX_DELAY` | No | `30.0` | Maximum retry delay (seconds) |
| `OPENCTI_CIRCUIT_THRESHOLD` | No | `5` | Failures before circuit opens |
| `OPENCTI_CIRCUIT_TIMEOUT` | No | `60` | Seconds before circuit recovery |
| `OPENCTI_EXTRA_OBSERVABLE_TYPES` | No | - | Custom observable types (comma-separated) |
| `OPENCTI_EXTRA_PATTERN_TYPES` | No | - | Custom pattern types (comma-separated) |
| `OPENCTI_LOG_FORMAT` | No | `json` | Log format: "json" or "text" |

### Token Storage Options

**Option 1: Environment variable (recommended)**
```bash
export OPENCTI_TOKEN="your-token"
```

**Option 2: .env file**
```
OPENCTI_TOKEN=your-token
```

**Option 3: Token file (most secure)**
```bash
mkdir -p ~/.config/opencti-mcp
echo "your-token" > ~/.config/opencti-mcp/token
chmod 600 ~/.config/opencti-mcp/token
```

---

## Verification

### Check Health

```bash
python -c "
from opencti_mcp.config import Config
from opencti_mcp.client import OpenCTIClient
config = Config.from_env()
client = OpenCTIClient(config)
result = client.validate_connection(skip_connectivity=False)
if result['valid']:
    ver = result.get('opencti_version', 'unknown')
    print(f'Connected to OpenCTI (version: {ver})')
else:
    for e in result.get('errors', []):
        print(f'ERROR: {e}')
for w in result.get('warnings', []):
    print(f'WARNING: {w}')
"
```

### Common Issues

| Error | Cause | Fix |
|-------|-------|-----|
| Connection refused | OpenCTI not running or wrong port | Check `docker ps \| grep opencti` and `OPENCTI_URL` |
| SSL certificate verify failed | Self-signed cert | Set `OPENCTI_SSL_VERIFY=false` (dev only) |
| 401 Unauthorized | Bad or expired API token | Regenerate token in OpenCTI UI |
| Name resolution failed | Wrong hostname | Verify `OPENCTI_URL` hostname is reachable |
| Using HTTP for remote server | Credentials sent in plaintext | Switch to `https://` in `OPENCTI_URL` |
| Empty results | No data in OpenCTI | Enable connectors to populate data (see above) |

---

## Quick Setup Script

For standalone installation, you can use the setup script instead of manual steps:

```bash
./setup.sh
```

This creates the virtual environment and installs dependencies. You still need to configure your OpenCTI credentials.

---

## Without OpenCTI

If you don't have OpenCTI and don't want to deploy it:

- **Skip opencti-mcp** during Claude-IR setup
- **forensic-rag-mcp** and **windows-triage-mcp** work independently
- You lose: hash reputation, IOC lookups, threat actor context
- You keep: knowledge search, file validation, process analysis

The other MCPs provide significant value without threat intelligence.

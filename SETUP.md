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

### Step 2: Configure the MCP

Create a `.env` file:
- **Claude-IR install:** Create at `/path/to/claude-ir/.env`
- **Standalone install:** Create at `/path/to/opencti-mcp/.env`

```
OPENCTI_URL=https://your-opencti-instance.example.com
OPENCTI_TOKEN=your-api-token-here
```

**Never paste tokens in chat.** Edit the file directly.

### Step 3: Verify Connection

```bash
cd opencti-mcp
source .venv/bin/activate
python -c "
from opencti_mcp import OpenCTIClient, Config
config = Config.load()
client = OpenCTIClient(config)
print('Connected!' if client.is_available() else 'Connection failed')
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

Access at: `http://localhost:8080`

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
| `OPENCTI_URL` | Yes | `http://localhost:8080` | OpenCTI instance URL |
| `OPENCTI_TOKEN` | Yes | - | API token from OpenCTI |
| `OPENCTI_READ_ONLY` | No | `true` | Disable write operations |
| `OPENCTI_TIMEOUT` | No | `60` | Request timeout (seconds) |
| `OPENCTI_SSL_VERIFY` | No | `true` | Verify SSL certificates |
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
from opencti_mcp import OpenCTIClient, Config
config = Config.load()
client = OpenCTIClient(config)
if client.is_available():
    print('✓ Connected to OpenCTI')
    # Test a simple query
    results = client.search_threat_actors('APT', limit=1)
    print(f'✓ Query working ({len(results)} results)')
else:
    print('✗ Connection failed')
"
```

### Common Issues

**Connection refused:**
- Check OPENCTI_URL is correct
- Verify OpenCTI is running: `docker ps | grep opencti`

**401 Unauthorized:**
- Check OPENCTI_TOKEN is correct
- Token may have expired - generate new one in OpenCTI

**SSL certificate errors:**
- For self-signed certs: `export OPENCTI_SSL_VERIFY=false` (dev only)
- For production: Use proper certificates

**Empty results:**
- OpenCTI may be empty - enable connectors to populate data
- Check connector status in OpenCTI UI

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
- **forensic-rag-mcp** and **forensic-triage-mcp** work independently
- You lose: hash reputation, IOC lookups, threat actor context
- You keep: knowledge search, file validation, process analysis

The other MCPs provide significant value without threat intelligence.

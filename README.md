# EPS Discount Service Integration API

A production-ready FastAPI service for monitoring and managing EPSDiscount.exe on remote Windows servers.

## Quick Start

### Prerequisites
- Python 3.12+ (for native deployment)
- Docker & Docker Compose (for containerized deployment)
- Remote server credentials

### Native Windows Deployment

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure `.env`** file:
   ```env
   USERNAME=Administrator
   PASSWORD=YourPassword
   SOURCE_FILE=D:\EPSNew\EPSDiscount.exe
   AUTO_START_EXE=false
   LOG_DIR=logs
   ```

3. **Start the service**:
   ```bash
   python run_service.py
   ```

   API available at: `http://localhost:8001`

### Docker Deployment

1. **Start the service**:
   ```bash
   docker-compose up -d
   ```

   API available at: `http://localhost:5001`

2. **View logs**:
   ```bash
   docker-compose logs -f
   ```

## API Endpoints

### 1. Health Check
**GET** `/api/health`

Check if the API is running.

### 2. Check Exe Status
**POST** `/api/check-exe-status`

Check if EPSDiscount.exe is running on specified servers.

**Request**:
```json
[
  {
    "outlet_code": "D007",
    "ip_address": "172.16.52.41"
  }
]
```

**Response**:
```json
{
  "endpoint": "check-exe-status",
  "timestamp": "2026-02-02T21:48:53.647000",
  "total_servers": 1,
  "data": [
    {
      "outlet_code": "D007",
      "ip_address": "172.16.52.41",
      "status": "Running",
      "available": true,
      "message": "EPSDiscount.exe is running"
    }
  ]
}
```

### 3. Run Exe
**POST** `/api/run-exe`

Start EPSDiscount.exe on specified servers.

**Request**: Same format as check-exe-status

**Response**: Returns execution status for each server

### 4. Deploy New Outlet
**POST** `/api/deploy-new-outlet`

Deploy and run EPSDiscount.exe on new outlet servers.

**Request**:
```json
{
  "servers": [
    {
      "outlet_code": "D008",
      "ip_address": "172.16.52.42"
    }
  ],
  "source_file": "D:\\EPSNew\\EPSDiscount.exe",
  "username": "Administrator",
  "password": "YourPassword"
}
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `USERNAME` | Remote server username | Administrator |
| `PASSWORD` | Remote server password | (required) |
| `SOURCE_FILE` | Path to EPSDiscount.exe | D:\EPSNew\EPSDiscount.exe |
| `AUTO_START_EXE` | Auto-start exe if offline | false |
| `LOG_DIR` | Log directory path | logs |
| `SERVER_PORT` | API port | 8001 |
| `SERVER_HOST` | API host | 0.0.0.0 |
| `PSEXEC_PATH` | Path to PsExec.exe | C:\Tools\PsExec.exe |

## Logging

Logs are written to date-based files in the `logs/` directory:
- `eps_discount_integration_log_YYYY-MM-DD.log` - All operations
- `eps_discount_integration_read_YYYY-MM-DD.log` - Read/check operations
- `eps_discount_integration_write_YYYY-MM-DD.log` - Write/deployment operations
- `eps_discount_integration_response_YYYY-MM-DD.log` - API responses with details
- `eps_discount_integration_failure_YYYY-MM-DD.log` - Errors and failures

Log format example:
```
2026-02-02 21:48:53,647 INFO     eps_discount_integration: outlet_code: D007 | ip_address: 172.16.52.41 | status: Running | available: true | message: EPSDiscount.exe is running
```

## Security

⚠️ **Important Security Notes**:
- Never commit `.env` file to version control (already in .gitignore)
- Use strong passwords for remote server credentials
- Restrict network access to the API port
- Run in a secure network environment
- Credentials are only stored in `.env` and memory, not in logs

## Status Codes

- **Running** - EPSDiscount.exe is running on the server
- **Not Running** - Server is online but exe is not running
- **Offline** - Server is not reachable
- **Unknown** - Unable to determine status

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Server is Offline" | Check network connectivity to target server |
| "ERROR: The user name or password is incorrect" | Verify credentials in `.env` |
| "Not Running" but exe is actually running | Check if process name matches "EPSDiscount.exe" |
| API not responding | Verify service is running: `http://localhost:8001/api/health` |
| Cannot reach Docker container | Ensure port 5001 is not in use on host machine |

## Project Structure

```
.
├── eps_discount_integration.py  # Main FastAPI service
├── run_service.py              # Service runner
├── Dockerfile                  # Docker image definition
├── docker-compose.yml          # Docker Compose configuration
├── requirements.txt            # Python dependencies
├── .env                        # Configuration (not in git)
├── logs/                       # Log files directory
└── README.md                   # This file
```

## Development

To modify the service:

1. Edit `eps_discount_integration.py`
2. Restart the service:
   ```bash
   # Native: Kill and restart run_service.py
   # Docker: docker-compose restart
   ```

## License

Internal use only.

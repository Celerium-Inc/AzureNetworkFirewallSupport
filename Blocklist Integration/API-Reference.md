# Azure Firewall Blocklist Integration - Technical Reference

## Execution Model

This function is timer-triggered and runs automatically on a schedule defined in the function.json configuration file.

```json
{
    "bindings": [
        {
            "name": "Timer",
            "type": "timerTrigger",
            "direction": "in",
            "schedule": "0 */15 * * * *"
        }
    ]
}
```

The default schedule is every 15 minutes (`0 */15 * * * *`). This can be modified by updating the function.json file.

## Operation Details

### Automatic Blocklist Update

The function performs the following operations automatically when triggered:

1. Authenticates with Azure using service principal credentials
2. Fetches IP addresses from the configured blocklist URL
3. Validates and processes the IP addresses
4. Updates Azure Firewall IP Groups efficiently
5. Updates the firewall rule collection to reference the IP Groups

#### Security Features
- No security gaps during updates
- Continuous protection while groups are updated
- Single atomic rule collection update
- Background completion for long-running operations

#### Execution Results
The function logs detailed information about its execution. Here's an example of successful execution results:

```json
{
  "status": "success",
  "message": "Successfully updated IP groups",
  "timestamp": "2024-03-28T18:52:47Z",
  "details": {
    "summary": {
      "groupsCreated": 0,
      "groupsUpdated": 4,
      "groupsDeleted": 1,
      "groupsProcessed": 4,
      "totalIps": 28788,
      "uniqueIps": 28788,
      "operationStart": "2024-03-28T18:42:16Z",
      "operationEnd": "2024-03-28T18:52:47Z",
      "durationSeconds": 631,
      "completed": true
    },
    "groupsUpdated": [
      {
        "name": "fw-blocklist-001",
        "count": 9000
      },
      {
        "name": "fw-blocklist-002",
        "count": 9000
      },
      {
        "name": "fw-blocklist-003",
        "count": 9000
      },
      {
        "name": "fw-blocklist-004",
        "count": 1788
      }
    ],
    "groupsDeleted": [
      {
        "name": "fw-blocklist-005"
      }
    ]
  }
}
```

## Manual Execution

While the function runs automatically on schedule, you can also trigger it manually:

1. Navigate to the Azure Portal
2. Go to Function App > Functions > blocklist
3. Click "Run"
4. View logs in the "Monitor" section

## Error Handling

### Error Log Format

When errors occur, they are logged in this format:

```
yyyy-MM-dd HH:mm:ss [Error] Detailed error description
```

### Common Error Types

| Type | Description | Example |
|------|-------------|---------|
| Authentication | Invalid credentials or permissions | "Failed to authenticate with Azure: Invalid client secret" |
| Resource | Resource not found or unavailable | "IP Group not found: fw-blocklist-001" |
| Rate Limiting | API throttling | "Rate limited by Azure API, retry after 30 seconds" |
| Validation | Invalid input data | "Invalid IP address format: 300.1.1.1" |
| Timeout | Operation exceeded time limit | "Timed out waiting for resource to reach state 'Succeeded'" |

## Timeouts and Retries

### Timeout Handling

Azure Firewall operations often take 5+ minutes to complete. The function:
- Uses extended timeouts (up to 6 minutes)
- Continues operations in the background even after timeout
- Reports success if operations are in progress but not completed

### Retry Strategy

| Operation | Max Retries | Backoff |
|-----------|------------|---------|
| IP Group Updates | 2 | Linear (3s, 6s) |
| Rule Collection Updates | 3 | Exponential (10s, 15s, 22s) |
| Resource State Checks | Continuous | Exponential with cap |

For long-running operations, success is reported even if the function execution time is exceeded, as Azure continues the operation.

## Function Configuration

For detailed configuration options, please refer to the [README.md](README.md) document. 
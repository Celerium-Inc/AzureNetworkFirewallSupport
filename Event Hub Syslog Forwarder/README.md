# Event Hub Syslog Forwarder

Azure Function that processes Azure Event Hub messages containing various log types (Flow Logs, DNS Queries, DNS Responses, Firewall Logs) and forwards them to a syslog server over SSL or UDP.

## Features

- **Multi-Log Type Support**: Process Virtual Network Flow Logs, Azure Firewall DNS Query Logs, DNS Response Logs, and Firewall Network/Application Rules Logs
- **Batch Processing**: Send multiple messages over a single SSL/TCP connection for improved performance
- **Configurable Timeouts**: Prevent hangs with configurable connection and I/O timeouts
- **Retry with Exponential Backoff**: Automatically retry failed transmissions with configurable backoff
- **Robust Timestamp Handling**: Flexible timestamp resolution that handles multiple record formats (PSCustomObject and Hashtable)
- **Protocol Support**: SSL/TLS or UDP for syslog transmission
- **Cloud Agnostic**: Works identically in Azure Public and Azure Government clouds
- **Comprehensive Error Handling**: Detailed error logging without failing the entire function

## Prerequisites

- Azure subscription
- Existing Event Hub namespace and Event Hub
- PowerShell 7.4
- Azure PowerShell modules:
  - Az.Accounts
  - Az.Resources
  - Az.Storage
  - Az.Functions
  - Az.EventHub
  - Az.ApplicationInsights
- App Service Plan (optional - Consumption plan auto-created if not specified)

## Supported Log Types

| Log Type | Detection | Description |
|----------|-----------|-------------|
| **Flow Logs** | `SubType = "FlowLog"` | Virtual Network Flow Logs from NSGs |
| **DNS Query Logs** | `category = "AZFWDnsQuery"` | Azure Firewall DNS Query Logs |
| **DNS Response Logs** | `category = "DnsResponse"` | Azure Firewall DNS Response Logs |
| **Firewall Logs** | Default | Azure Firewall Network/Application Rules Logs |

## Configuration

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `SYSLOG_SERVER` | Syslog server hostname or IP address |
| `SYSLOG_PORT` | Syslog server port |
| `SYSLOG_PROTOCOL` | Protocol to use: `SSL` or `UDP` (defaults to SSL) |
| `EVENT_HUB_NAME` | Name of the Event Hub |
| `EVENTHUB_CONNECTION` | Event Hub connection string |

### Optional Environment Variables - Timeouts

| Variable | Default | Description |
|----------|---------|-------------|
| `SYSLOG_CONNECT_TIMEOUT_MS` | 5000 | TCP connection timeout in milliseconds |
| `SYSLOG_IO_TIMEOUT_MS` | 5000 | Read/Write operation timeout in milliseconds |

### Optional Environment Variables - Retry Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SYSLOG_MAX_RETRIES` | 3 | Maximum number of retry attempts on failure |
| `SYSLOG_RETRY_BACKOFF_MS` | 500 | Base delay between retries in milliseconds |
| `SYSLOG_RETRY_BACKOFF_MAX_MS` | 5000 | Maximum delay cap between retries in milliseconds |

### Runtime Environment Variables (Auto-configured)

| Variable | Default |
|----------|---------|
| `FUNCTIONS_WORKER_RUNTIME` | powershell |
| `FUNCTIONS_WORKER_RUNTIME_VERSION` | 7.4 |
| `FUNCTIONS_EXTENSION_VERSION` | ~4 |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | Auto-configured |
| `APPINSIGHTS_INSTRUMENTATIONKEY` | Auto-configured |

## Setup

### NOTE
These commands have been tested via cloud shell

1. Upload the content:
   You will need to copy the PowerShell scripts and eventhub folder with the following layout:
   ```
   - forward/
     - deploy.ps1
     - cleanup.ps1
     - src/
       - function.json
       - host.json
       - run.ps1
   ```

2. Deploy using PowerShell:

### Deployment Scenarios

> **Note**: App Service Plan is optional. If not specified, a Consumption (Y1) plan will be automatically created. You can also specify an existing plan with `-AppServicePlanName`.

#### Scenario 1: Simple Deployment (Auto-creates Consumption Plan)

```powershell
# Deploy with auto-created Consumption plan
./forward/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "eastus" `
    -FunctionAppName "your-func-name" `
    -SyslogServer "syslog.example.com" `
    -SyslogPort 514 `
    -EventHubName "your-eventhub" `
    -EventHubConnection "your-connection-string" `
    -Protocol "SSL"
```

#### Scenario 2: Use Existing App Service Plan

```powershell
# First, find existing App Service Plans in your subscription
Get-AzAppServicePlan | Select-Object Name, ResourceGroup, Sku

# Deploy using an existing plan (Premium, Basic, etc.)
./forward/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "eastus" `
    -FunctionAppName "your-func-name" `
    -SyslogServer "syslog.example.com" `
    -SyslogPort 514 `
    -EventHubName "your-eventhub" `
    -EventHubConnection "your-connection-string" `
    -Protocol "SSL" `
    -AppServicePlanName "existing-plan-name" `
    -AppServicePlanResourceGroup "plan-rg"  # Optional, defaults to same RG
```

#### Scenario 3: Azure US Government Cloud

```powershell
# With auto-created Consumption plan
./forward/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "usgovvirginia" `
    -FunctionAppName "your-func-name" `
    -SyslogServer "syslog.example.com" `
    -SyslogPort 514 `
    -EventHubName "your-eventhub" `
    -EventHubConnection "your-connection-string" `
    -Protocol "SSL" `
    -AzureCloud AzureUSGovernment

# Or with an existing plan
./forward/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "usgovvirginia" `
    -FunctionAppName "your-func-name" `
    -SyslogServer "syslog.example.com" `
    -SyslogPort 514 `
    -EventHubName "your-eventhub" `
    -EventHubConnection "your-connection-string" `
    -Protocol "SSL" `
    -AppServicePlanName "existing-plan-name" `
    -AzureCloud AzureUSGovernment
```

The deployment script will:
1. Verify Azure connection and resource group (cloud-aware)
2. Create or update storage account (auto-named from function app name)
3. Create or update Application Insights
4. Create or update Function App
5. Configure runtime settings and environment variables
6. Validate required permissions
7. Deploy function code with retry logic (cloud-aware Kudu URL)
8. Restart the function app

### Deployment Validation
The script performs several validation steps:
1. Resource group existence
2. Storage account naming
3. Required permissions
4. Function runtime compatibility
5. File deployment success

## Architecture

### Message Processing Flow

```
Event Hub → Azure Function → Log Type Detection → Format Syslog Message → Batch Send to Syslog Server
```

### Performance Optimizations

1. **Connection Reuse**: All messages from a single Event Hub batch are sent over one SSL/TCP connection instead of opening a new connection per message.

2. **Batch Processing**: Messages are collected and sent in batches, reducing network overhead.

3. **Async Connect with Timeout**: Uses non-blocking connection with configurable timeout to prevent function hangs.

### Resilience Features

1. **Retry with Exponential Backoff**: Failed transmissions are automatically retried with increasing delays.

2. **Graceful Degradation**: Syslog transmission failures are logged but don't cause the function to fail, preventing message loss in Event Hub.

3. **Robust Timestamp Resolution**: Handles multiple timestamp field formats and falls back to current UTC time if no timestamp is found.

## Error Handling and Monitoring

### Error Handling
The function includes comprehensive error handling:
- Input validation for required environment variables
- Connection timeout handling
- Retry logic with exponential backoff
- Detailed error logging
- Non-blocking error handling (syslog failures don't crash the function)

### Monitoring
Monitor the function using:
- Azure Portal > Function App > Functions > EventHubTrigger > Monitor
- Application Insights logs and metrics
- Function execution logs

### Common Issues

| Issue | Possible Cause | Solution |
|-------|---------------|----------|
| Connection timeout | Syslog server unreachable | Check network connectivity, firewall rules |
| SSL handshake failure | Certificate issues | Verify syslog server certificate |
| Messages not arriving | Event Hub binding issue | Check EVENTHUB_CONNECTION string |
| Function timeout | Too many messages | Increase timeout or reduce batch size |

### Troubleshooting Steps

1. Check function logs in Azure Portal:
   - Go to Function App > Functions > EventHubTrigger > Monitor
   - Or use Azure CLI:
```powershell
az functionapp logs tail `
    --name "your-func-name" `
    --resource-group "your-rg"
```

2. Verify environment variables:
   - Check SYSLOG_SERVER and SYSLOG_PORT are correct
   - Validate Event Hub connection string

3. Test network connectivity:
   - Verify syslog server is reachable from Azure
   - Check any firewall or NSG rules

4. Increase timeouts if needed:
   - Set `SYSLOG_CONNECT_TIMEOUT_MS` and `SYSLOG_IO_TIMEOUT_MS` to higher values

## Syslog Message Formats

### Flow Log Format
```
<13>TimeGenerated={timestamp} Type=FlowLog FaSchemaVersion={version} 
    TimeProcessed={timestamp} FlowIntervalStart={timestamp} FlowIntervalEnd={timestamp}
    FlowStartTime={timestamp} FlowEndTime={timestamp} FlowType={type}
    SrcIp={ip} DstIp={ip} DstPort={port} Protocol={protocol} L7Protocol={protocol}
    Direction={direction} Status={status} BytesDestToSrc={bytes} BytesSrcToDest={bytes}
    ...
```

### DNS Query Log Format
```
<13>TimeGenerated={timestamp} Type=DnsQueryLog 
    ResourceId={id} SrcIp={ip} SrcPort={port} QueryId={id}
    QueryType={type} QueryClass={class} QueryName={name} Protocol={protocol}
    RequestSize={size} ResponseCode={code} ResponseSize={size}
    ...
```

### DNS Response Log Format
```
<13>TimeGenerated={timestamp} Type=DnsResponseLog 
    ResourceId={id} QueryName={name} QueryType={type} ResponseCode={code}
    SrcIpAddr={ip} SrcPort={port} DstIpAddr={ip} DstPort={port}
    DnsAnswerIndex={index} DnsAnswerType={type} DnsAnswerRData={data}
    ...
```

### Firewall Log Format
```
<13>TimeGenerated={timestamp} Type=FirewallLog 
    ResourceId={id} Protocol={protocol} SrcIp={ip} SrcPort={port}
    DstIp={ip} DstPort={port} Action={action}
    Policy={policy} RuleCollectionGroup={group} RuleCollection={collection}
    Rule={rule} ActionReason={reason}
```

## Cleanup

Remove all deployed resources:
```powershell
./forward/cleanup.ps1 `
    -ResourceGroupName "your-rg" `
    -FunctionAppName "your-func-name"
```

For sovereign clouds (e.g., US Gov):
```powershell
./forward/cleanup.ps1 `
    -ResourceGroupName "your-rg" `
    -FunctionAppName "your-func-name" `
    -AzureCloud AzureUSGovernment
```

## Version History

### v2.0.0 (Current)
- Added batch sending over single SSL connection for improved performance
- Added configurable connection and I/O timeouts
- Added retry logic with exponential backoff
- Added robust timestamp resolution for multiple record formats
- Improved error handling and logging

### v1.0.0
- Initial release with basic syslog forwarding

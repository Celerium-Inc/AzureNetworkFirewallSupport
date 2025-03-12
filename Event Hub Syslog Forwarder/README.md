# Event Hub Syslog Forwarder

Azure Function that forwards Azure Event Hub messages to a Syslog server over SSL/UDP. This function processes various Azure log types including Flow Logs, DNS Queries, DNS Responses, and Firewall Logs.

## Features

- Secure log forwarding:
  - SSL/TLS
  - UDP
- Support for multiple log types:
  - Virtual Network Flow Logs
  - Azure Firewall DNS Query Logs
  - Azure Firewall DNS Response Logs
  - Azure Firewall Network/Application Rules Logs
- Real-time log processing
- Configurable syslog formatting
- Detailed error handling and logging
- High-volume log processing with batching
- In-portal code editing support

## Prerequisites

- Azure subscription
- Existing Event Hub namespace and Event Hub containing logs
- Syslog server with SSL/TLS or UDP support
- Network connectivity between Function App and Syslog server
- PowerShell 7.2 or later
- Azure PowerShell modules:
  - Az.Accounts
  - Az.Resources
  - Az.Storage
  - Az.Functions

## Setup

1. Prepare Event Hub:
   - Ensure your Event Hub is receiving logs (Flow Logs, Firewall Logs, etc.)
   - Get Event Hub Connection String:
     1. Navigate to your Event Hub namespace in Azure Portal
     2. Go to "Shared access policies"
     3. Select a policy (e.g., "RootManageSharedAccessKey" or create a new one with Manage permissions)
     4. Copy the "Connection string-primary key"

2. Deploy using PowerShell:
```powershell
./deploy.ps1 `
    -ResourceGroupName "your-resource-group" `
    -Location "eastus" `
    -FunctionAppName "your-function-name" `
    -StorageAccountName "yourstorage" `
    -SyslogServer "your-syslog-server" `
    -SyslogPort 6514 `
    -Protocol "SSL" `
    -EventHubName "your-event-hub-name" `
    -EventHubConnection "Endpoint=sb://..."
```

### Deployment Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| ResourceGroupName | Existing resource group name | "syslog-forwarder-rg" |
| Location | Azure region for deployment | "eastus" |
| FunctionAppName | Globally unique function app name | "syslog-forwarder-func" |
| StorageAccountName | Globally unique storage account name | "syslogstore" |
| SyslogServer | Syslog server hostname/IP | "syslog.company.com" |
| SyslogPort | Syslog server port (SSL:6514, UDP:514) | 6514 |
| Protocol | "SSL" or "UDP" | "SSL" |
| EventHubName | Name of your Event Hub | "firewall-logs" |
| EventHubConnection | Event Hub connection string | "Endpoint=sb://..." |

The deployment script will:
1. Create a storage account (if it doesn't exist)
2. Create and configure the function app
3. Set up all required environment variables
4. Deploy the function code
5. Enable in-portal editing

## Configuration

### Environment Variables
All environment variables are automatically configured during deployment:
- `SYSLOG_SERVER`: Hostname/IP of your syslog server
- `SYSLOG_PORT`: Port number for syslog server
- `SYSLOG_PROTOCOL`: Protocol to use ("SSL" or "UDP")
- `EVENT_HUB_NAME`: Name of the Event Hub
- `EVENTHUB_CONNECTION`: Event Hub connection string

### Modifying the Function

You can modify the function code directly in the Azure Portal:
1. Go to your Function App
2. Select "Functions" from the left menu
3. Click on "EventHubTrigger"
4. Select "Code + Test"
5. Make your changes and save

## Log Types and Formatting

### 1. Flow Logs
```
<13>TimeGenerated=timestamp Type=FlowLog SrcIp=ip DstIp=ip Protocol=protocol Action=action ...
```
- Traffic flows through Network Security Groups
- Source/destination IPs, ports, protocols
- Flow timing and status information

### 2. DNS Query Logs
```
<13>TimeGenerated=timestamp Type=DnsQueryLog QueryName=name QueryType=type ResponseCode=code ...
```
- DNS queries processed by Azure Firewall
- Query details (name, type, class)
- Response information

### 3. DNS Response Logs
```
<13>TimeGenerated=timestamp Type=DnsResponseLog QueryName=name AnswerType=type AnswerData=data ...
```
- Detailed DNS response information
- Answer records with types and TTLs
- Resolution paths and policies

### 4. Firewall Logs
```
<13>TimeGenerated=timestamp Type=FirewallLog SrcIp=ip DstIp=ip Action=action Rule=rule ...
```
- Traffic allowed/denied by firewall rules
- Rule collection and policy information
- Connection details

## Monitoring

Monitor the function using:
- Azure Portal > Function App > Functions > EventHubTrigger > Monitor
- Application Insights (if enabled)
- Function execution logs
- Syslog server logs

### Available Metrics
- Log processing duration
- Successful/failed transmissions
- Batch sizes
- Error rates

## Troubleshooting

1. Check function logs in Azure Portal:
   - Go to Function App > Functions > EventHubTrigger > Monitor
   - Or use Azure CLI:
```powershell
az functionapp logs tail `
    --name "your-function-name" `
    --resource-group "your-resource-group"
```

2. Common issues:
   - Event Hub connectivity issues
   - Syslog server connection failures
   - SSL/TLS certificate validation errors
   - Network connectivity problems
   - Missing environment variables

## Cleanup

Remove all deployed resources:
```powershell
./cleanup.ps1 `
    -ResourceGroupName "your-resource-group" `
    -FunctionAppName "your-function-name" `
    -StorageAccountName "yourstorage"
```

The cleanup script will:
1. Prompt for confirmation
2. Remove the Function App
3. Remove the Storage Account 
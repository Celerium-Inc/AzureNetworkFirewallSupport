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
- Configurable syslog formatting
- Detailed error handling and logging
- High-volume log processing
- Automatic retry logic

## Prerequisites

- Azure subscription
- Event Hub namespace and Event Hub
- Syslog server with SSL/TLS or UDP support
- Network connectivity between Function App and Syslog server
- PowerShell 7.2 or later
- Azure PowerShell modules:
  - Az.Accounts
  - Az.Resources
  - Az.Storage
  - Az.Functions
  - Az.EventHub

## Setup

1. Deploy using PowerShell:
```powershell
./deploy.ps1 `
    -ResourceGroupName "syslog-rg" `
    -Location "eastus" `
    -FunctionAppName "syslog-func" `
    -StorageAccountName "sysstore" `
    -EventHubNamespace "your-namespace" `
    -EventHubName "your-eventhub" `
    -SyslogServer "your-syslog-server" `
    -SyslogPort "your-syslog-port" `
    -Protocol "SSL"  # or "UDP"
```

2. Configure environment variables:
```powershell
az functionapp config appsettings set `
    --name "syslog-func" `
    --resource-group "syslog-rg" `
    --settings `
        SYSLOG_SERVER=your-syslog-server `
        SYSLOG_PORT=your-syslog-port `
        SYSLOG_PROTOCOL=SSL
```

## Configuration

### Required Environment Variables
- `SYSLOG_SERVER`: Hostname/IP of your syslog server
- `SYSLOG_PORT`: Port number for syslog server
- `SYSLOG_PROTOCOL`: Protocol to use ("SSL" or "UDP")

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

## Protocol Support

### Protocol Selection
The function supports both SSL/TLS and UDP protocols through the `SYSLOG_PROTOCOL` environment variable:
```powershell
# For SSL/TLS
SYSLOG_PROTOCOL=SSL

# For UDP
SYSLOG_PROTOCOL=UDP
```

## Monitoring

Monitor the function using:
- Azure Application Insights
- Function execution logs
- Syslog server logs

### Available Metrics
- Log processing duration
- Successful/failed transmissions
- Batch sizes
- Retry counts
- Error rates

## Troubleshooting

1. Check function logs:
```powershell
az functionapp logs tail `
    --name "syslog-func" `
    --resource-group "syslog-rg"
```

2. Common issues:
   - Missing environment variables
   - SSL/TLS certificate issues
   - Network connectivity problems
   - Event Hub trigger configuration
   - Syslog server capacity limits

## Cleanup

Remove all deployed resources:
```powershell
./cleanup.ps1 `
    -ResourceGroupName "syslog-rg" `
    -FunctionAppName "syslog-func" `
    -StorageAccountName "sysstore"
``` 
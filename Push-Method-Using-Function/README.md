# Azure Function Log Ingestion

This collection of Azure Functions processes Event Hub messages containing various Azure logs and forwards them to a syslog server using either SSL/TLS or UDP transport. The functions handle multiple types of Azure logs including Flow Logs, DNS Queries, DNS Responses, and Firewall Logs.

## Overview

Each function:
1. Receives log messages from Azure Event Hub
2. Processes and formats the log data
3. Forwards formatted messages to a syslog server
4. Handles multiple log types in a single function

### Available Functions

- `trigger-ssl.ps1` - Forwards logs using SSL/TLS encryption
- `trigger-udp.ps1` - Forwards logs using UDP transport

## Prerequisites

1. Azure Resources:
   - Azure Event Hub namespace and Event Hub instance
   - Azure Function App for hosting PowerShell scripts
   - Storage Account for Function App

2. For SSL/TLS version:
   - SSL certificate from trusted Certificate Authority (CA)
   - Certificate accessible from Function App

3. Syslog server configured for:
   - SSL/TLS connections (for SSL version)
   - UDP connections (for UDP version)
   - Appropriate listening ports
   - Log message processing

## Setup

### 1. Create Azure Function App

```bash
# Create resource group (if needed)
az group create \
  --name <resource-group> \
  --location <location>

# Create storage account
az storage account create \
  --name <storage-account> \
  --resource-group <resource-group> \
  --location <location> \
  --sku Standard_LRS

# Create Function App
az functionapp create \
  --name <app-name> \
  --resource-group <resource-group> \
  --storage-account <storage-account> \
  --runtime powershell \
  --functions-version 4 \
  --os-type Windows
```

### 2. Configure App Settings

```bash
# For SSL version
az functionapp config appsettings set \
  --name <app-name> \
  --resource-group <resource-group> \
  --settings \
    SYSLOG_SERVER=syslog.example.com \
    SYSLOG_PORT=6514

# For UDP version
az functionapp config appsettings set \
  --name <app-name> \
  --resource-group <resource-group> \
  --settings \
    SYSLOG_SERVER=syslog.example.com \
    SYSLOG_PORT=6514
```

### 3. Deploy Function Code

1. Create function.json:
```json
{
  "bindings": [
    {
      "type": "eventHubTrigger",
      "name": "eventHubMessages",
      "direction": "in",
      "eventHubName": "<event-hub-name>",
      "connection": "EventHubConnection",
      "cardinality": "many",
      "consumerGroup": "$Default"
    }
  ]
}
```

2. Deploy the code using Azure Functions Core Tools or VS Code

## Log Types Supported

### 1. Virtual Network Flow Logs
- Traffic flows through Network Security Groups (NSGs)
- Contains source/destination IPs, ports, protocols
- Flow timing and status information

### 2. Azure Firewall DNS Query Logs
- DNS queries processed by Azure Firewall
- Query details (name, type, class)
- Response information

### 3. Azure Firewall DNS Response Logs
- Detailed DNS response information
- Answer records
- Resolution paths and policies

### 4. Azure Firewall Network/Application Rules Logs
- Traffic allowed/denied by firewall rules
- Rule collection and policy information
- Connection details

## Troubleshooting

1. Check Function App logs:
   - Application Insights
   - Function execution logs
   - Platform logs

2. Common issues:
   - Event Hub connectivity
   - SSL certificate problems (SSL version)
   - Network connectivity
   - Syslog server availability
   - Message formatting errors

3. Monitor Function metrics:
   - Execution count
   - Execution duration
   - Memory usage
   - Failure count

## Error Handling

Both functions include comprehensive error handling for:
- Event Hub message processing
- JSON parsing
- Timestamp conversion
- Network transmission
- SSL/TLS negotiation (SSL version)
- Message formatting

## Log Message Format

All logs are formatted as key-value pairs with a syslog priority prefix (<13>):

```
<13>TimeGenerated=<timestamp> Type=<log-type> Field1=Value1 Field2=Value2 ...
```

Example fields by log type:

1. Flow Logs:
   - TimeGenerated, TimeProcessed
   - FlowType, FlowDirection, FlowStatus
   - SrcIp, DstIp, Protocol
   - BytesSrcToDest, BytesDestToSrc

2. DNS Query Logs:
   - TimeGenerated
   - QueryName, QueryType, QueryClass
   - Protocol, ResponseCode
   - RequestSize, ResponseSize

3. DNS Response Logs:
   - TimeGenerated
   - QueryName, ResponseCode
   - DnsAnswerType, DnsAnswerTTL
   - ResolutionPath

4. Firewall Logs:
   - TimeGenerated
   - Protocol, Action
   - SrcIp, DstIp
   - Policy, Rule 
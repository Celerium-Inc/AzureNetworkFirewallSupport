# Event Hub Syslog Forwarder

Azure Function that forwards syslog messages to Azure Event Hub. Supports both UDP and SSL/TLS protocols for syslog ingestion.

## Features
- Receive syslog messages via UDP or SSL/TLS
- Forward messages to Azure Event Hub
- Configurable protocol and port settings
- Comprehensive error handling and logging
- Secure service principal authentication
- Custom role-based access control
- Optimized deployment process with retries
- Automatic storage account naming

## Prerequisites
- Azure subscription
- Existing Event Hub namespace and Event Hub
- PowerShell 7.2 or later
- Azure PowerShell modules:
  - Az.Accounts
  - Az.Resources
  - Az.Storage
  - Az.Functions
  - Az.EventHub
  - Az.ApplicationInsights

## Required Permissions
The function requires the following permissions:

### Role Assignments
1. **Azure Event Hubs Data Receiver** role on the Event Hub namespace
   - Required for reading from Event Hub
   - Scope: Microsoft.EventHub/namespaces

2. **Storage Blob Data Contributor** role on the storage account
   - Required for Function App storage access
   - Scope: Microsoft.Storage/storageAccounts

### Permission Details
- Microsoft.EventHub/namespaces/eventhubs/messages/send
- Microsoft.Storage/storageAccounts/*
- Microsoft.Web/sites/config/write

The deployment script will validate these permissions and provide guidance if any are missing.

## Configuration

### Required Environment Variables
- `SYSLOG_SERVER`: Syslog server address
- `SYSLOG_PORT`: Syslog server port
- `EVENT_HUB_NAME`: Event Hub name
- `EVENTHUB_CONNECTION`: Event Hub connection string
- `PROTOCOL`: Syslog protocol (SSL or UDP)

### Optional Environment Variables
- `FUNCTIONS_WORKER_RUNTIME`: PowerShell (default)
- `FUNCTIONS_WORKER_RUNTIME_VERSION`: 7.2 (default)
- `FUNCTIONS_EXTENSION_VERSION`: ~4 (default)
- `APPLICATIONINSIGHTS_CONNECTION_STRING`: Auto-configured
- `APPINSIGHTS_INSTRUMENTATIONKEY`: Auto-configured

## Setup

### NOTE
These commands have been tested via cloud shell

1. Upload the content:
   You will need to copy the PowerShell scripts and src folder with the following layout:
   ```
   - deploy.ps1
   - cleanup.ps1
   - src
     - function.json
     - host.json
     - run.ps1
   ```

2. Deploy using PowerShell:
```powershell
./deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "eastus" `
    -FunctionAppName "your-func-name" `
    -SyslogServer "syslog.example.com" `
    -SyslogPort 514 `
    -EventHubName "your-eventhub" `
    -EventHubConnection "your-connection-string" `
    -Protocol "SSL"  # Optional, defaults to SSL
```

The deployment script will:
1. Verify Azure connection and resource group
2. Create or update storage account (auto-named from function app name)
3. Create or update Application Insights
4. Create or update Function App
5. Configure runtime settings and environment variables
6. Validate required permissions
7. Deploy function code with retry logic
8. Restart the function app

### Deployment Validation
The script performs several validation steps:
1. Resource group existence
2. Storage account naming
3. Required permissions
4. Function runtime compatibility
5. File deployment success

## Error Handling and Monitoring

### Error Handling
The function includes comprehensive error handling:
- Input validation
- Connection error handling with retries
- Detailed error logging
- Consistent error responses

### Monitoring
Monitor the function using:
- Azure Portal > Function App > Functions > EventHubTrigger > Monitor
- Application Insights logs and metrics
- Function execution logs

### Common Issues
1. Missing role assignments
2. Event Hub connection problems
3. Network connectivity errors
4. Rate limiting on Event Hub
5. Function app deployment issues

### Troubleshooting Steps
1. Check function logs in Azure Portal:
   - Go to Function App > Functions > EventHubTrigger > Monitor
   - Or use Azure CLI:
```powershell
az functionapp logs tail `
    --name "your-func-name" `
    --resource-group "your-rg"
```

2. Verify permissions:
   - Check role assignments in IAM
   - Validate Event Hub connection
   - Test network connectivity

## Cleanup

Remove all deployed resources:
```powershell
./cleanup.ps1 `
    -ResourceGroupName "your-rg" `
    -FunctionAppName "your-func-name"
```

The cleanup script will remove:
1. Function App
2. Application Insights
3. Associated storage account
4. Any related resources

## Documentation

### [API Reference](API-Reference.md)
- API endpoints and usage
- Message format specifications
- Error handling
- Implementation details 
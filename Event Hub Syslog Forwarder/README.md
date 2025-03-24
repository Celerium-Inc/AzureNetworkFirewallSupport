# Event Hub Syslog Forwarder

Azure Function that forwards syslog messages to Azure Event Hub. Supports both UDP and SSL/TLS protocols for syslog ingestion.

## Features
- Receive syslog messages via UDP or SSL/TLS
- Forward messages to Azure Event Hub
- Configurable protocol and port settings
- Comprehensive error handling and logging
- Secure TLS certificate management
- Custom role-based access control
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

## Required Permissions
The function requires the following permissions:

### Role Assignments
1. **Event Hub Data Sender** role on the Event Hub
   - Required for:
     - Sending messages to Event Hub
     - Managing Event Hub connections

2. **Contributor** role on the resource group
   - Required for:
     - Creating and managing function resources
     - Managing storage accounts
     - Configuring network settings

### Permission Details
- Microsoft.EventHub/namespaces/eventhubs/messages/send
- Microsoft.Web/sites/config/write
- Microsoft.Storage/storageAccounts/*

### How to Assign Permissions
1. Go to the Azure Portal
2. Navigate to your Event Hub
3. Click "Access control (IAM)"
4. Click "+ Add" > "Add role assignment"
5. Select "Event Hub Data Sender"
6. Search for and select your function app's managed identity
7. Click "Review + assign"

## Configuration

### Required Environment Variables
- `SYSLOG_SERVER`: Syslog server address
- `SYSLOG_PORT`: Syslog server port
- `EVENT_HUB_NAME`: Event Hub name
- `EVENT_HUB_CONNECTION`: Event Hub connection string
- `PROTOCOL`: Syslog protocol (SSL or UDP)

### Optional Environment Variables
- `LOG_VERBOSITY`: Logging detail level (1=Basic, 2=Verbose)
- `MAX_BATCH_SIZE`: Maximum batch size for Event Hub messages (default: 1000)
- `BATCH_TIMEOUT`: Timeout for batch sending in seconds (default: 30)
- `SSL_CERT_PATH`: Path to SSL certificate (required for SSL protocol)
- `SSL_KEY_PATH`: Path to SSL private key (required for SSL protocol)

## Setup

### NOTE
These commands have only been tested via cloud shell

1. Upload the content:
   You will need to copy the PowerShell scripts deploy and clean,
   as well as the full src folder with the following layout:
   ```
   - deploy.ps1
   - cleanup.ps1
   - src
     - function.json
     - host.json
     - requirements.psd1
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
    -Protocol "SSL"
```

The deployment script will:
1. Create a storage account with name derived from the function app name
   - Removes special characters and ensures valid Azure storage naming
   - Example: "your-func-name" → "yourfuncnamestorage"
2. Create and configure the function app
3. Set up all required environment variables
4. Deploy the function code
5. Enable in-portal editing

## Error Handling and Monitoring

### Error Handling
The function includes comprehensive error handling:
- Input validation
- Connection error handling with retries
- Detailed error logging
- Consistent error responses

### Monitoring
Monitor the function using:
- Azure Portal > Function App > Functions > syslog > Monitor
- Application Insights logs and metrics
- Function execution logs

### Common Issues
1. SSL certificate configuration issues
2. Event Hub connection problems
3. Network connectivity errors
4. Rate limiting on Event Hub
5. Message size limitations

### Troubleshooting Steps
1. Check function logs in Azure Portal:
   - Go to Function App > Functions > syslog > Monitor
   - Or use Azure CLI:
```powershell
az functionapp logs tail `
    --name "your-func-name" `
    --resource-group "your-rg"
```

2. Verify permissions:
   - Check Event Hub Data Sender role
   - Validate Event Hub connection string
   - Test network connectivity

## Cleanup

Remove all deployed resources:
```powershell
./cleanup.ps1 `
    -ResourceGroupName "your-rg" `
    -FunctionAppName "your-func-name"
```

## Documentation

### [API Reference](API-Reference.md)
- API endpoints and usage
- Message format specifications
- Error handling
- Implementation details 
# Azure Firewall Blocklist Integration

Azure Function that manages IP blocklists in Azure Firewall using IP Groups and Rule Collection Groups. Automatically fetches and updates blocked IPs from an external source.

## Features
- Fetch and validate IP addresses from external blocklists
- Automatically split large IP lists into multiple IP Groups
- Create and update Azure Firewall rules
- Support for both inbound and outbound blocking
- Configurable group sizes and limits
- Comprehensive error handling and logging

## Configuration
### Required Environment Variables
- `SUBSCRIPTION_ID`: Azure subscription ID
- `RESOURCE_GROUP`: Resource group containing the firewall
- `FIREWALL_NAME`: Azure Firewall name
- `POLICY_NAME`: Firewall Policy name
- `TENANT_ID`: Azure AD tenant ID
- `CLIENT_ID`: Azure AD application ID
- `CLIENT_SECRET`: Azure AD application secret
- `BLKLIST_URL`: URL to fetch blocked IPs

### Optional Environment Variables
- `MAX_TOTAL_IPS`: Maximum total IPs to process (default: 50000)
- `MAX_IPS_PER_GROUP`: Maximum IPs per group (default: 5000)
- `MAX_IP_GROUPS`: Maximum number of IP groups (default: 10)
- `BASE_IP_GROUP_NAME`: Base name for IP groups (default: "fw-blocklist")
- `RULE_COLLECTION_GROUP_NAME`: Name of rule collection group (default: "CeleriumRuleCollectionGroup")
- `RULE_COLLECTION_NAME`: Name of rule collection (default: "Blocked-IP-Collection")
- `RULE_PRIORITY`: Priority for firewall rules (default: 100)
- `LOG_VERBOSITY`: Logging detail level (1=Basic, 2=Verbose)

## API Endpoints

### Test Connection
```http
GET /api/blocklist?action=test&code={function_key}
```

### Update Blocklist
```http
GET /api/blocklist?action=update&code={function_key}
```

### Unblock IPs
```http
POST /api/blocklist?action=unblock&code={function_key}
Content-Type: application/json

{
    "IpsToUnblock": [
        "1.1.1.1",
        "2.2.2.2"
    ]
}
```

## Deployment
Use the provided `deploy.ps1` script to deploy the function:
```powershell
./deploy.ps1 -ResourceGroup <rg-name> -Location <location>
```

## Error Handling
The function includes comprehensive error handling:
- Input validation
- Azure API error handling with retries
- Detailed error logging
- Consistent error responses

## Prerequisites

- Azure subscription
- Existing Azure Firewall and Firewall Policy
- PowerShell 7.2 or later
- Azure PowerShell module

## Quick Start

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-directory>
```

2. Deploy using PowerShell:
```powershell
./deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "eastus" `
    -FunctionAppName "your-func-name" `
    -StorageAccountName "yourstorage" `
    -FirewallPolicyName "your-policy" `
    -FirewallName "your-firewall" `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -ClientSecret "your-client-secret" `
    -BlocklistUrl "https://your-blocklist-url"
```

3. Test the deployment:
```powershell
# Get your function key from Azure Portal > Function App > App keys
$functionKey = "your-function-key"
$functionApp = "your-func-name"

# Test connectivity
Invoke-RestMethod "https://$functionApp.azurewebsites.net/api/blocklist?action=test&code=$functionKey"
```

## Documentation

### [Setup Guide](Setup.md)
- Prerequisites
- Detailed deployment steps
- Configuration options
- Troubleshooting guide
- Cleanup instructions

### [API Reference](API-Reference.md)
- API endpoints and usage
- Detailed action descriptions
- Request/response formats
- Error handling
- Implementation details

## Example Usage

### Update Blocklist
```powershell
# Update blocklist from configured URL
Invoke-RestMethod "https://$functionApp.azurewebsites.net/api/blocklist?action=update&code=$functionKey"
```

### Unblock IPs
```powershell
# Unblock specific IPs
$body = @{
    IpsToUnblock = @("1.1.1.1", "2.2.2.2")
} | ConvertTo-Json

Invoke-RestMethod "https://$functionApp.azurewebsites.net/api/blocklist?action=unblock&code=$functionKey" `
    -Method Post `
    -Body $body `
    -ContentType "application/json"
```

## Cleanup

To remove all deployed resources:
```powershell
./cleanup.ps1 `
    -ResourceGroupName "your-rg" `
    -FunctionAppName "your-func-name" `
    -StorageAccountName "yourstorage"
```

## License
[MIT License](LICENSE)
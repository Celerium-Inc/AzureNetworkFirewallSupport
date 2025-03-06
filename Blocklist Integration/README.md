# Azure Firewall Blocklist Integration

This Azure Function integrates external IP blocklists with Azure Firewall using IP Groups and Rule Collection Groups.

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
GET /api/blocklist?action=test
```

### Update Blocklist
```http
GET /api/blocklist?action=update
```

### Unblock IPs
```http
GET /api/blocklist?action=unblock&IPs=1.1.1.1,2.2.2.2
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

1. Deploy the function app:
```powershell
./deploy.ps1 -ResourceGroupName "your-rg" `
             -Location "your-location" `
             -FunctionAppName "your-func-name" `
             -StorageAccountName "your-storage"
```

2. Configure the function app settings:
```powershell
az functionapp config appsettings set --name <function-app-name> --resource-group <resource-group> --settings "FIREWALL_NAME=<your-firewall-name>" "POLICY_NAME=<your-policy-name>" "TENANT_ID=<tenant-id>" "CLIENT_ID=<client-id>" "CLIENT_SECRET=<client-secret>" "SUBSCRIPTION_ID=<subscription-id>" "RESOURCE_GROUP=<resource-group>" "BLKLIST_URL=<your-blocklist-url>"
```

3. Test the deployment:
```http
GET https://<function-app-name>.azurewebsites.net/api/blocklist?action=test&code=<function-key>
```

## Documentation

- [Setup Guide](Setup.md) - Detailed setup instructions
- [API Reference](API.md) - API documentation and examples

## License

[MIT License](LICENSE)
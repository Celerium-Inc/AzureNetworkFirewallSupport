# Azure Firewall Blocklist Integration

Azure Function that manages IP blocklists in Azure Firewall using IP Groups and Rule Collection Groups. Automatically fetches and updates blocked IPs from an external source.

## Features
- Fetch and validate IP addresses from external blocklists
- Automatically split large IP lists into multiple IP Groups
- Create and update Azure Firewall rules
- Support for both inbound and outbound blocking
- Configurable group sizes and limits
- Comprehensive error handling and logging
- Secure service principal authentication
- Custom role-based access control

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
- Azure PowerShell modules:
  - Az.Accounts
  - Az.Resources
  - Az.Storage
  - Az.Functions
  - Az.Network

## Quick Start

1. Deploy using PowerShell:
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

2. Remove the function and its storage resources using PowerShell:
```powershell
./cleanup.ps1 `
    -ResourceGroupName "your-rg" `
    -FunctionAppName "your-func-name" `
    -StorageAccountName "yourstorage"
```

## Documentation

### [API Reference](API-Reference.md)
- API endpoints and usage
- Detailed action descriptions
- Request/response formats
- Error handling
- Implementation details

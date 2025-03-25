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
- Optimized IP group management
  - Reuses existing groups when possible
  - Updates groups in place to minimize API calls
  - Only deletes unused groups
- Efficient IP distribution across groups

## IP Group Management

### Group Creation and Updates
- IP groups are created and updated as needed
- Existing groups are reused when possible to minimize API operations
- Only unused groups are deleted
- Groups are named using sequential numbers (e.g., fw-blocklist-001, fw-blocklist-002)
- Groups can contain any number of IPs, from 1 to MAX_IPS_PER_GROUP

### Group Management Strategy
The function uses an optimized approach:
1. First removes IP group references from firewall rules
2. Calculates required groups for current IPs
3. Updates existing groups where possible
4. Creates new groups only when needed
5. Deletes only unused groups
6. Updates firewall rules with final group configuration

### Example Group Update Process
```
Initial state:
fw-blocklist-001 (5000 IPs)
fw-blocklist-002 (5000 IPs)
fw-blocklist-003 (3000 IPs)
fw-blocklist-004 (2000 IPs)

New IP distribution needed (12000 IPs):
1. Update fw-blocklist-001 with new 5000 IPs
2. Update fw-blocklist-002 with new 5000 IPs
3. Update fw-blocklist-003 with new 2000 IPs
4. Delete fw-blocklist-004 (no longer needed)
```

### Configuration Options
| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| BASE_IP_GROUP_NAME | Base name for IP groups | "fw-blocklist" | "custom-blocklist" |
| MAX_TOTAL_IPS | Maximum total IPs to process | 50000 | 100000 |
| MAX_IPS_PER_GROUP | Maximum IPs per group | 5000 | 10000 |
| MAX_IP_GROUPS | Maximum number of groups | 10 | 15 |

### Example Group Structure
```
fw-blocklist-001 (4500 IPs)
fw-blocklist-002 (3200 IPs)
fw-blocklist-003 (1800 IPs)
```

### Manual Cleanup
If you need to remove empty groups:
1. First update firewall rules to remove group references
2. Then delete the groups
3. Update rule collection to use remaining groups

**Note:** Manual cleanup should be done with caution and during maintenance windows.

### Monitoring and Logging
The function provides detailed logging about IP group operations:

#### Group Status Logging
```powershell
# Log format examples:
"2024-03-21 16:45:23 [Information] Found 3 IP Groups matching pattern 'fw-blocklist-*'"
"2024-03-21 16:45:24 [Information] Updating existing group fw-blocklist-001 with 5000 IPs"
"2024-03-21 16:45:25 [Information] Creating new group fw-blocklist-003 with 2000 IPs"
"2024-03-21 16:45:26 [Information] Deleting unused group fw-blocklist-004"
```

#### Monitoring Points
1. **Group Creation/Updates**
   - Number of IPs per group
   - Total number of groups
   - Group update success/failure

2. **Empty Groups**
   - Groups using placeholder IPs
   - Last update timestamp
   - Update frequency

3. **API Operations**
   - Request success/failure rates
   - Response times
   - Rate limiting impacts

#### Available Metrics
- Total IPs processed
- IPs per group
- Group update frequency
- API call latency
- Error rates


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

## Required Permissions
The service principal (application) used by this function requires the following permissions:

### Role Assignments
1. **Network Contributor** role on the resource group
   - Required for:
     - Reading and writing IP Groups
     - Managing network resources
     - Updating firewall rules and policies

2. **Contributor** role on the resource group
   - Required for:
     - Creating and managing IP Groups
     - Updating firewall policies
     - Managing rule collection groups

### Permission Details
- Microsoft.Network/ipGroups/read
- Microsoft.Network/ipGroups/write
- Microsoft.Network/ipGroups/delete
- Microsoft.Network/firewallPolicies/read
- Microsoft.Network/firewallPolicies/write
- Microsoft.Network/firewallPolicies/ruleCollectionGroups/read
- Microsoft.Network/firewallPolicies/ruleCollectionGroups/write

### How to Assign Permissions
1. Go to the Azure Portal
2. Navigate to your Resource Group
3. Click "Access control (IAM)"
4. Click "+ Add" > "Add role assignment"
5. Select the required role ("Network Contributor" or "Contributor")
6. Search for and select your service principal
7. Click "Review + assign"

Note: The function will validate these permissions during deployment and warn if any are missing.

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

## Setup

### NOTE
These commands have only been run via cloud shell

1. Upload the content:
   You will need to copy the powershell scripts deploy and clean,
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
    -FirewallPolicyName "your-policy" `
    -FirewallName "your-firewall" `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -ClientSecret "your-client-secret" `
    -BlocklistUrl "https://your-blocklist-url"
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
- Azure API error handling with retries
- Detailed error logging
- Consistent error responses

### Monitoring
Monitor the function using:
- Azure Portal > Function App > Functions > blocklist > Monitor
- Application Insights logs and metrics
- Function execution logs

### Common Issues
1. Service Principal permission issues
2. IP Group creation failures
3. Firewall policy update errors
4. Blocklist URL connectivity problems
5. Rate limiting on Azure APIs

### Troubleshooting Steps
1. Check function logs in Azure Portal:
   - Go to Function App > Functions > blocklist > Monitor
   - Or use Azure CLI:
```powershell
az functionapp logs tail `
    --name "your-func-name" `
    --resource-group "your-rg"
```

2. Verify permissions:
   - Check service principal roles in IAM
   - Validate access to IP Groups and Firewall Policy
   - Test blocklist URL accessibility

## Cleanup

Remove all deployed resources:
```powershell
./cleanup.ps1 `
    -ResourceGroupName "your-rg" `
    -FunctionAppName "your-func-name" `
```

## Documentation

### [API Reference](API-Reference.md)
- API endpoints and usage
- Detailed action descriptions
- Request/response formats
- Error handling
- Implementation details

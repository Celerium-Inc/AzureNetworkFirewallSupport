# Setup Guide

## Prerequisites
1. Azure subscription with:
   - Resource group for deployment
   - Azure Firewall and Firewall Policy
   - Permissions to create:
     - Function App
     - Storage Account
     - IP Groups
     - Firewall Rules

2. Local development environment:
   - PowerShell 7.2 or later
   - Azure PowerShell module
   - Git (optional)

## Installation Steps

1. Clone or download the repository:
```bash
git clone <repository-url>
cd <repository-directory>
```

2. Connect to Azure:
```powershell
Connect-AzAccount -UseDeviceAuthentication
```

3. Deploy the function:
```powershell
./deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "your-location" `
    -FunctionAppName "your-func-name" `
    -StorageAccountName "your-storage" `
    -FirewallPolicyName "your-policy" `
    -FirewallName "your-firewall" `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -ClientSecret "your-client-secret" `
    -BlocklistUrl "your-blocklist-url"
```

4. Get your function key:
   - Go to Azure Portal
   - Navigate to your Function App
   - Select "App keys"
   - Copy the default function key

5. Test the deployment:
```powershell
$functionKey = "your-function-key"
$functionApp = "your-func-name"

# Test connectivity
Invoke-RestMethod "https://$functionApp.azurewebsites.net/api/blocklist?action=test&code=$functionKey"

# Update blocklist
Invoke-RestMethod "https://$functionApp.azurewebsites.net/api/blocklist?action=update&code=$functionKey"
```

## Configuration

### Required Environment Variables
Configure these in your Function App settings:
- `SUBSCRIPTION_ID`: Azure subscription ID
- `RESOURCE_GROUP`: Resource group containing firewall
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
- `LOG_VERBOSITY`: Logging detail level (1=Basic, 2=Verbose)

## Cleanup

To remove all deployed resources:
```powershell
./cleanup.ps1 `
    -ResourceGroupName "your-rg" `
    -FunctionAppName "your-func-name" `
    -StorageAccountName "your-storage"
```

## Troubleshooting

### Common Issues

1. Module Loading Errors:
   - Check function logs for module loading errors
   - Verify requirements.psd1 contains correct module versions

2. Authentication Errors:
   - Verify service principal credentials
   - Check RBAC permissions
   - Ensure all environment variables are set correctly

3. CORS Issues:
   - Verify host.json contains correct Azure Portal domains
   - Check CORS settings in Azure Portal

### Logs and Monitoring

Access logs through:
1. Azure Portal > Function App > Functions > blocklist > Monitor
2. Application Insights (if enabled)
3. Function execution logs

## Next Steps

1. Review the [Technical Overview](Overview.md)
2. Check the [API Reference](API.md)
3. Set up monitoring and alerts
4. Configure backup procedures

## Security Considerations

1. Store credentials securely
2. Use minimum required permissions
3. Regularly rotate service principal secrets
4. Monitor function access logs
5. Review blocked IP lists periodically 
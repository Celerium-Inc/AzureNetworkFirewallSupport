# Setup Guide

## Prerequisites

### Azure Resources
- Azure subscription
- Resource group
- Azure Firewall and Firewall Policy
- Permissions to create:
  - Function App
  - Storage Account
  - IP Groups
  - Firewall Rules

### Local Development
- PowerShell 7.2 or later
- Azure PowerShell module
- Git (optional)

## Deployment Steps

1. **Prepare Configuration**
   
   Gather these required values:
   - Resource Group name
   - Azure region (e.g., "eastus")
   - Function App name (must be globally unique)
   - Storage Account name (must be globally unique)
   - Firewall Policy name
   - Firewall name
   - Azure AD details:
     - Tenant ID
     - Client ID (Application ID)
     - Client Secret
   - Blocklist URL

2. **Deploy Resources**

   Run the deployment script:
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

3. **Verify Deployment**
   - Get your function key from Azure Portal
   - Test connectivity using the test endpoint
   - Monitor function logs in Azure Portal

## Configuration Options

### Environment Variables
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| MAX_TOTAL_IPS | No | 50000 | Maximum total IPs to process |
| MAX_IPS_PER_GROUP | No | 5000 | Maximum IPs per group |
| MAX_IP_GROUPS | No | 10 | Maximum number of IP groups |
| LOG_VERBOSITY | No | 2 | Logging detail (1=Basic, 2=Verbose) |

## Cleanup

To remove all deployed resources:
```powershell
./cleanup.ps1 `
    -ResourceGroupName "your-rg" `
    -FunctionAppName "your-func-name" `
    -StorageAccountName "yourstorage"
```

## Troubleshooting

### Common Issues

1. **Deployment Fails**
   - Verify Azure permissions
   - Check resource name availability
   - Ensure PowerShell version 7.2+

2. **Authentication Errors**
   - Verify service principal credentials
   - Check RBAC permissions
   - Confirm environment variables

3. **Function Errors**
   - Check function logs in Azure Portal
   - Verify blocklist URL accessibility
   - Confirm IP Group limits

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
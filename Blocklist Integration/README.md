# Azure Firewall Blocklist Integration

An Azure Function that automatically updates Azure Firewall IP Groups with blocklists from external sources.

## Overview

This solution:
- Fetches IP addresses from external blocklists
- Updates Azure Firewall IP Groups with these addresses
- Maintains continuous protection with no security gaps during updates
- Handles large IP sets efficiently
- Provides comprehensive logging and error handling

## Features

- **Continuous Protection**: Updates IP Groups without creating security gaps
- **Intelligent IP Distribution**: Efficiently manages thousands of IPs across groups
- **Optimized Performance**: Batched operations with rate limit awareness
- **Enhanced Reliability**: Comprehensive error handling and retry logic
- **Extended Timeout Handling**: Gracefully handles Azure Firewall's long provisioning times
- **Automated Updates**: Configurable timer-triggered execution
- **API Access**: HTTP endpoints for testing and manual operations

## Architecture

The solution uses:
- Azure Functions (PowerShell runtime)
- Azure Firewall Premium or Standard
- Azure Firewall IP Groups
- Azure Firewall Policy Rule Collections

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|:--------:|
| `SUBSCRIPTION_ID` | Azure subscription ID | - | ✓ |
| `RESOURCE_GROUP` | Resource group containing firewall | - | ✓ |
| `FIREWALL_NAME` | Azure Firewall name | - | ✓ |
| `POLICY_NAME` | Firewall Policy name | - | ✓ |
| `BLKLIST_URL` | URL to fetch blocked IPs | - | ✓ |
| `TENANT_ID` | Azure AD tenant ID | - | ✓ |
| `CLIENT_ID` | Azure AD application ID | - | ✓ |
| `CLIENT_SECRET` | Azure AD application secret | - | ✓ |
| `MAX_TOTAL_IPS` | Maximum IPs to process | 50000 | |
| `MAX_IPS_PER_GROUP` | Maximum IPs per group | 5000 | |
| `MAX_IP_GROUPS` | Maximum number of groups | 10 | |
| `BASE_IP_GROUP_NAME` | Base name for IP groups | "fw-blocklist" | |
| `RULE_COLLECTION_GROUP_NAME` | Rule collection group name | "CeleriumRuleCollectionGroup" | |
| `RULE_COLLECTION_NAME` | Rule collection name | "Blocked-IP-Collection" | |
| `RULE_PRIORITY` | Rule priority | 100 | |
| `LOG_VERBOSITY` | Logging level (1=Basic, 2=Verbose) | 2 | |

### Timer Schedule

The function runs on a schedule defined in the `function.json` file. By default, it runs every 15 minutes:

```json
{
    "schedule": "0 */15 * * * *"
}
```

To modify the schedule:
1. Edit the `function.json` file in the function app
2. Update the `schedule` property with a valid CRON expression
3. Save the changes

Common CRON expressions:
- `0 */15 * * * *` - Every 15 minutes (default)
- `0 */30 * * * *` - Every 30 minutes
- `0 0 * * * *` - Every hour
- `0 0 */2 * * *` - Every 2 hours

### Performance Optimization

For optimal performance:

1. **IP Group Size**: Azure IP Groups can contain up to 5,000 IPs each
   - Use `MAX_IPS_PER_GROUP=5000` (default) for best efficiency
   - Using smaller values creates unnecessary groups

2. **Group Count**: `MAX_IP_GROUPS` limits total groups created
   - When total IPs > (MAX_IPS_PER_GROUP × MAX_IP_GROUPS), IPs are distributed evenly
   - Example: 29,000 IPs with MAX_IP_GROUPS=10 means ~2,900 IPs per group
   
3. **Recommended Configurations**:
   - ~30,000 IPs: Use 6 groups with 5,000 IPs each
   - ~50,000 IPs: Use 10 groups with 5,000 IPs each
   - >50,000 IPs: Increase both settings proportionally

## Security Approach

The function maintains continuous protection during updates:

1. **No Security Gaps**: Existing rules remain active during the entire update process
2. **Secure Updates**: IP groups are updated while still referenced in the firewall
3. **Atomic Rule Updates**: Final rule collection changes happen in a single operation
4. **Graceful Timeout Handling**: Updates complete in the background even if function times out

## Deployment

1. Upload the solution files with this structure:
   ```
   - block
      - deploy.ps1
      - cleanup.ps1
      - src/
         - function.json
         - host.json
         - requirements.psd1
         - run.ps1
   ```

2. Execute the deployment script:
   ```powershell
   ./block/deploy.ps1 `
       -ResourceGroupName "your-rg" `
       -Location "your-loc" `
       -FunctionAppName "your-func-name" `
       -FirewallPolicyName "your-policy" `
       -FirewallName "your-firewall" `
       -TenantId "your-tenant-id" `
       -ClientId "your-client-id" `
       -ClientSecret "your-client-secret" `
       -BlocklistUrl "https://your-blocklist-url"
   ```

## Monitoring and Troubleshooting

### Logging

Access logs through:
- Azure Portal > Function App > Functions > blocklist > Monitor
- Application Insights logs and metrics

### Common Issues and Resolutions

1. **Permission Errors**
   - Verify the service principal has Network Contributor role
   - Check access to IP Groups and Firewall Policy

2. **IP Group Updates Failing**
   - Verify the blocklist URL is accessible
   - Check format of IPs in the blocklist
   - Review logs for specific API errors

3. **Timeout Errors**
   - Message: "Timed out waiting for resource to reach state 'Succeeded'"
   - Status: These are now handled gracefully - updates continue in background
   - Action: None required unless lasting >10 minutes

4. **Rate Limiting**
   - The function implements exponential backoff for retries
   - Consider adjusting the update frequency if persistent

## Performance Metrics

Typical performance characteristics:
- ~30,000 IPs processed in 5-8 minutes
- IP Group updates: 1-2 seconds per group
- Rule Collection updates: 3-5 minutes (Azure limitation)

## Cleanup

To remove all deployed resources:
```powershell
./cleanup.ps1 `
    -ResourceGroupName "your-rg" `
    -FunctionAppName "your-func-name"
```

## API Documentation

For API endpoints and usage details, see [API-Reference.md](API-Reference.md).

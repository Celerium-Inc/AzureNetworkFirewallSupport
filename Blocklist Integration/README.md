# Azure Firewall Blocklist Integration

An Azure Function that automatically updates Azure Firewall IP Groups with blocklists from external sources.

## Overview

This solution:
- Fetches IP addresses from external blocklists
- Updates Azure Firewall IP Groups with these addresses
- Creates both outbound blocking rules and an empty DNAT collection for customer use
- Maintains continuous protection with no security gaps during updates
- Handles large IP sets efficiently
- Provides comprehensive logging and error handling
- Enforces secure communications with TLS 1.2 and HTTPS-only connections

## Features

- **Continuous Protection**: Updates IP Groups without creating security gaps
- **Intelligent IP Distribution**: Efficiently manages thousands of IPs across groups
- **Optimized Performance**: Batched operations with rate limit awareness
- **Enhanced Reliability**: Comprehensive error handling and retry logic
- **Extended Timeout Handling**: Gracefully handles Azure Firewall's long provisioning times
- **Automated Updates**: Configurable timer-triggered execution
- **API Access**: HTTP endpoints for testing and manual operations
- **Secure Communications**: TLS 1.2 support with HTTPS-only connections

## Architecture

The solution uses:
- Azure Functions (PowerShell runtime)
- Azure Firewall Premium or Standard
- Azure Firewall IP Groups
- Azure Firewall Policy Rule Collections

### Rule Collection Structure

The function creates a single rule collection group (`CeleriumRuleCollectionGroup`) with priority 100 containing:

1. **Blackhole DNAT Collection** (Priority 100)
   - Empty DNAT rule collection for customer use
   - Customers can add their own DNAT rules here
   
2. **Blocked-IP Collection** (Priority 101)
   - Contains outbound blocking rules only
   - Automatically populated with IPs from the blocklist

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|:--------:|
| `SUBSCRIPTION_ID` | Azure subscription ID | - | ✓ |
| `RESOURCE_GROUP` | Resource group containing firewall | - | ✓ |
| `FIREWALL_NAME` | Azure Firewall name | - | ✓ |
| `POLICY_NAME` | Firewall Policy name | - | ✓ |
| `BLKLIST_URL` | URL to fetch blocked IPs (HTTPS only) | - | ✓ |
| `TENANT_ID` | Azure AD tenant ID | - | ✓ |
| `CLIENT_ID` | Azure AD application ID | - | ✓ |
| `CLIENT_SECRET` | Azure AD application secret | - | ✓ |
| `MAX_TOTAL_IPS` | Maximum IPs to process | 50000 | |
| `MAX_IPS_PER_GROUP` | Maximum IPs per group | 5000 | |
| `MAX_IP_GROUPS` | Maximum number of groups | 10 | |
| `BASE_IP_GROUP_NAME` | Base name for IP groups | "fw-blocklist" | |
| `RULE_COLLECTION_GROUP_NAME` | Rule collection group name | "CeleriumRuleCollectionGroup" | |
| `RULE_COLLECTION_NAME` | Rule collection name | "Blocked-IP" | |
| `RULE_PRIORITY` | Blocked-IP collection priority | 101 | |
| `BLACKHOLE_RULE_PRIORITY` | Blackhole DNAT collection priority | 100 | |
| `GROUP_RULE_PRIORITY` | Rule collection group priority | 100 | |
| `LOG_VERBOSITY` | Logging level (1=Basic, 2=Verbose) | 2 | |
| `ENFORCE_HTTPS_ONLY` | Force HTTPS for blocklist URL | true | |

### Blackhole DNAT Collection

The function creates an empty DNAT rule collection called "Blackhole" for customer use:

- **Purpose**: Provides a dedicated space for custom DNAT rules
- **Priority**: 100 (executes before the blocking rules)
- **Management**: Customers can add their own DNAT rules through Azure Portal or ARM templates
- **Best Practice**: Use this collection for any custom NAT rules to ensure proper rule ordering

### Security Settings

The function enforces the following security settings:

- **TLS Version**: Uses TLS 1.2 for all communications
- **HTTPS Enforcement**: Rejects non-HTTPS blocklist URLs when `ENFORCE_HTTPS_ONLY` is enabled (default)
- **Function App Settings**: Configures the Function App with HTTPS-only access

### Timer Schedule

The function runs on a schedule defined in the `function.json` file. By default, it runs every 15 minutes:

```json
{
    "schedule": "0 */10 * * * *"
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
5. **Outbound-Only Blocking**: Creates only outbound blocking rules

### Rule Priority Order

Rules are processed in this order:
1. **Blackhole DNAT Collection** (Priority 100) - Customer's custom DNAT rules
2. **Blocked-IP Collection** (Priority 101) - Automated outbound blocking rules

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

3. After deployment, the function will create:
   - A rule collection group named "CeleriumRuleCollectionGroup" (priority 100)
   - An empty "Blackhole" DNAT collection (priority 100) for customer use
   - A "Blocked-IP" collection (priority 101) with outbound blocking rules

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

5. **Rule Collection Issues**
   - The function creates both Blackhole (DNAT) and Blocked-IP (Filter) collections
   - Ensure the Azure Firewall Policy supports both collection types
   - Check that rule priorities don't conflict with existing rules

## Performance Metrics

Typical performance characteristics:
- ~30,000 IPs processed in 5-8 minutes
- IP Group updates: 1-2 seconds per group
- Rule Collection Group updates: 3-5 minutes (Azure limitation)
- Creates 2 rule collections per update: Blackhole (DNAT) and Blocked-IP (Filter)

## Customer Usage

### Using the Blackhole DNAT Collection

After deployment, customers can add their own DNAT rules to the "Blackhole" collection:

1. **Through Azure Portal**:
   - Navigate to Azure Firewall Policy > Rule collection groups
   - Select "CeleriumRuleCollectionGroup"
   - Edit the "Blackhole" collection
   - Add custom DNAT rules as needed

2. **Through ARM Templates or PowerShell**:
   - Target the existing "Blackhole" collection within "CeleriumRuleCollectionGroup"
   - Add rules with priorities that don't conflict with existing rules

## Cleanup

To remove all deployed resources:
```powershell
./block/cleanup.ps1 `
    -ResourceGroupName "your-rg" `
    -FunctionAppName "your-func-name"
```

## API Documentation

For API endpoints and usage details, see [API-Reference.md](API-Reference.md).

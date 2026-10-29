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
- **Managed Identity**: Deploy enables a system-assigned managed identity. Runtime Azure auth still uses the service principal (`CLIENT_ID` / `CLIENT_SECRET`) until a later migration.
- **Cloud-aware hosting default**: `-HostingPlan Auto` infers Classic or Flex from an existing named plan. Without one, it deploys a new Linux Flex Consumption Function App in Azure Public and a Windows Basic B1 Function App in Azure Government. Azure does not support in-place Classic↔Flex migration — use a new Function App name.

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
| `AZURE_CLOUD` | Cloud selection: `AzurePublicCloud`, `AzureUSGovernment` | AzurePublicCloud | |
| `AZURE_CLOUD_ENVIRONMENT` | Alternative alias (simple names accepted, e.g., `azure`, `azureusgovernment`) | - | |
| `AZURE_AUTHORITY_HOST` | Override AAD authority host (e.g., `https://login.microsoftonline.us`) | Derived from cloud | |
| `AZURE_ARM_ENDPOINT` | Override ARM endpoint (e.g., `https://management.usgovcloudapi.net`) | Derived from cloud | |

> If `AZURE_AUTHORITY_HOST` and `AZURE_ARM_ENDPOINT` are provided, they take precedence. Otherwise, `AZURE_CLOUD` or `AZURE_CLOUD_ENVIRONMENT` selects the correct endpoints. Defaults target the public cloud.

### Sovereign Cloud Configuration (Important)

To avoid AADSTS900382 cross-cloud errors, ensure the authentication authority and ARM endpoint match your tenant/cloud:

- **Azure Public** (default):
  - `AZURE_CLOUD=AzurePublicCloud` (or `AZURE_CLOUD_ENVIRONMENT=azure`)
  - Authority: `https://login.microsoftonline.com`
  - ARM: `https://management.azure.com`
- **Azure US Government**:
  - Set `AZURE_CLOUD=AzureUSGovernment` (or `AZURE_CLOUD_ENVIRONMENT=azureusgovernment`), or set `AZURE_AUTHORITY_HOST=https://login.microsoftonline.us` and `AZURE_ARM_ENDPOINT=https://management.usgovcloudapi.net`

The function will request tokens from the correct authority and target the appropriate ARM endpoint (scope `<ARM>/.default`) automatically based on these settings.

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
- **Function App Settings**: Configures HTTPS-only access and enables HTTP/2 to satisfy the Microsoft Defender recommendation
- **Secure storage (optional)**: Use an existing locked-down storage account, or let deploy create private endpoints and disable public access. Both paths VNet-integrate the Function App.

### Timer Schedule

The function runs on a schedule defined in the `function.json` file. By default, it runs every **10 minutes**:

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
- `0 */10 * * * *` - Every 10 minutes (default)
- `0 */15 * * * *` - Every 15 minutes
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

## Script parameters

### `deploy.ps1`

#### Required

| Parameter | Description |
|-----------|-------------|
| `-ResourceGroupName` | Resource group for the Function App, storage (when created), Application Insights, and deploy-owned private endpoints. Must already exist. |
| `-Location` | Azure region for new resources (for example `eastus` or `USGov Virginia`). |
| `-FunctionAppName` | Function App name. Also used to derive the default storage account name (`<sanitized-name>storage`, max 24 characters) and the default plan name (`<FunctionAppName>-plan`). |
| `-FirewallPolicyName` | Azure Firewall Policy the function updates. |
| `-FirewallName` | Azure Firewall name written to app settings. |
| `-TenantId` | Microsoft Entra tenant ID for the runtime service principal. |
| `-ClientId` | Application (client) ID for the runtime service principal. |
| `-ClientSecret` | Client secret for the runtime service principal. |
| `-BlocklistUrl` | HTTPS URL of the IP blocklist to import. |

#### Optional hosting and cloud

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-AzureCloud` | `AzurePublicCloud` | `AzurePublicCloud` or `AzureUSGovernment`. Selects ARM login environment and storage DNS suffix (`core.windows.net` vs `core.usgovcloudapi.net`). |
| `-AuthorityHost` | Derived from `-AzureCloud` | Override AAD authority (for example `https://login.microsoftonline.us`). |
| `-ArmEndpoint` | Derived from `-AzureCloud` | Override ARM endpoint (for example `https://management.usgovcloudapi.net`). |
| `-HostingPlan` | `Auto` | `Auto`, `Classic`, or `FlexConsumption`. Auto infers Classic or Flex from an existing named plan; otherwise Flex in Azure Public and Classic B1 in Azure Government. Flex is not available in Azure Government. Classic↔Flex in-place migration is not supported. |
| `-FlexInstanceMemoryMB` | `512` | Flex instance memory: `512`, `2048`, or `4096`. Ignored for Classic. |
| `-AppServicePlanName` | Auto-created `<FunctionAppName>-plan` | Existing plan to use. With `-HostingPlan Auto`, the plan SKU selects Classic or Flex. |
| `-AppServicePlanResourceGroup` | `-ResourceGroupName` | Resource group of `-AppServicePlanName` when the plan lives in another group. |

#### Optional secure storage

VNet and subnets are **customer prerequisites**. Deploy never creates a VNet. Secure paths require `Az.Network` and `Az.PrivateDns`. Consumption (Y1) is rejected because it cannot use regional VNet integration.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-StorageAccountName` | Derived from `-FunctionAppName` | Existing storage account to use as-is. When set, deploy does **not** create private endpoints or change the account firewall. Requires `-VNetName` and `-IntegrationSubnetName`. |
| `-StorageAccountResourceGroup` | `-ResourceGroupName` | Resource group of `-StorageAccountName` when the account lives in another group. |
| `-VNetName` | None | Existing virtual network used for Function App integration (and, on create-and-lock, private endpoints). |
| `-VNetResourceGroup` | `-ResourceGroupName` | Resource group of `-VNetName` when the VNet lives in another group. |
| `-IntegrationSubnetName` | None | Existing subnet for Function App VNet integration. Classic requires delegation `Microsoft.Web/serverFarms`. Flex requires `Microsoft.App/environments`. |
| `-PrivateEndpointSubnetName` | None | Existing subnet for storage private endpoints. Required only for create-and-lock. Must be different from the integration subnet. Ignored when `-StorageAccountName` is set. |

**Which combination to pass**

| Path | Parameters to pass | What deploy does |
|------|--------------------|------------------|
| Public (default) | None of the secure-storage parameters | Creates or reuses a public `Standard_LRS` account named from the Function App. |
| Existing storage | `-StorageAccountName` + `-VNetName` + `-IntegrationSubnetName` | Uses that account unchanged. VNet-integrates the Function App, enables route-all, and on Classic sets `vnetContentShareEnabled`. |
| Create and lock | `-VNetName` + `-IntegrationSubnetName` + `-PrivateEndpointSubnetName` (no storage name) | Creates storage, then sets `publicNetworkAccess=Disabled` and `defaultAction=Deny` after private endpoints and VNet integration exist. Flex publishes the package while storage is still public, then creates blob/file/queue/table private endpoints, private DNS, and VNet integration, and locks the account. A rerun where those private endpoints already exist re-enables the public endpoint only for the upload, confirms Azure kept `publicNetworkAccess=Enabled` and `defaultAction=Allow`, and locks it again. Classic creates the private endpoints first and locks storage before the Kudu upload. |

Partial combinations throw (for example a storage name without a VNet, or a VNet without the subnets required for that path).

**Flex prerequisite:** Azure Public Flex secure-storage (existing account or create-and-lock) requires the subscription to have `Microsoft.App` registered. Deploy calls `Get-AzResourceProvider` / `Register-AzResourceProvider` and waits until `RegistrationState` is `Registered`. If registration is denied, run `Register-AzResourceProvider -ProviderNamespace Microsoft.App` with a subscription Owner or Contributor, then rerun deploy. Classic (including Azure Government) does not need this.

### `cleanup.ps1`

| Parameter | Required | Default | Description |
|-----------|:--------:|---------|-------------|
| `-ResourceGroupName` | Yes | | Resource group that contains the Function App and deploy-created resources. |
| `-FunctionAppName` | Yes | | Function App to delete. Also used to derive the default storage account and plan names. |
| `-FirewallPolicyName` | Yes | | Firewall Policy whose `CeleriumRuleCollectionGroup` and `fw-blocklist-*` IP Groups are removed. |
| `-AzureCloud` | No | `AzurePublicCloud` | `AzurePublicCloud` or `AzureUSGovernment`. |

Cleanup does not take VNet or storage-name parameters. It deletes deploy-owned storage and `{storage}-{blob\|file\|queue\|table}-pe` private endpoints tagged `ManagedBy=AzureNetworkFirewallSupport`. Customer-owned storage (used with `-StorageAccountName` on deploy), VNets, subnets, and shared private DNS zones are preserved.

## Deployment

1. Upload the solution files with this structure:
   ```
   - block
      - deploy.ps1
      - cleanup.ps1
      - src/
         - function.json
         - host.json
         - profile.ps1
         - requirements.psd1
         - run.ps1
   ```

2. Execute the deployment script:

### Deployment Scenarios

> **Hosting notes**
> - Default `-HostingPlan` is `Auto`: an existing named plan is inferred from its SKU. Without an existing named plan, Azure Public resolves to `FlexConsumption` and Azure Government resolves to `Classic` with an auto-created Basic B1 plan.
> - Explicit `-HostingPlan Classic` or `-HostingPlan FlexConsumption` overrides Auto inference.
> - Classic targeting an existing Flex app/plan (or the reverse) **throws**. Use a new Function App/plan name to change modes.
> - App Service Plan is optional for Classic: if omitted, a Basic (B1) plan is created. Pass `-AppServicePlanName` for an existing Windows plan.
> - Blocklist Flex instances default to 512 MB. Use `-FlexInstanceMemoryMB 2048` or `4096` to override the default.
> - Deployment applies app settings non-interactively for both Classic and Flex.
> - `host.json` sets `managedDependency.enabled = false` (Flex-safe; no PowerShell Gallery auto-install).
> - Deploy overwrites `wwwroot/profile.ps1` with a no-op file so the platform template does not call `Connect-AzAccount -Identity` (Az modules are not installed).
> - Secure storage is opt-in. See [Optional secure storage](#optional-secure-storage) for the public, existing-account, and create-and-lock parameter combinations.

#### Scenario 1: Simple Azure Public Deployment (Auto-creates Flex Consumption Plan)
**Best for:** New serverless deployments in Azure Public

```powershell
./block/deploy.ps1 `
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

#### Scenario 2: Use Existing App Service Plan
**Best for:** Premium or Dedicated hosting requirements

```powershell
./block/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "eastus" `
    -FunctionAppName "your-func-name" `
    -FirewallPolicyName "your-policy" `
    -FirewallName "your-firewall" `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -ClientSecret "your-client-secret" `
    -BlocklistUrl "https://your-blocklist-url" `
    -AppServicePlanName "existing-plan-name" `
    -AppServicePlanResourceGroup "plan-rg"  # Optional, defaults to same RG
```

With `-HostingPlan Auto`, the existing plan's SKU selects Classic or Flex. Pass `-HostingPlan Classic` explicitly when you want to require Classic rather than infer it.

#### Scenario 3: Azure US Government Cloud (Classic only)
**Note:** Flex Consumption is **not** available in Azure Government. Works with auto-created Basic B1 or an existing Windows plan.

```powershell
# With auto-created Basic B1 plan
./block/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "USGov Virginia" `
    -FunctionAppName "your-func-name" `
    -FirewallPolicyName "your-policy" `
    -FirewallName "your-firewall" `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -ClientSecret "your-client-secret" `
    -BlocklistUrl "https://your-blocklist-url" `
    -AzureCloud AzureUSGovernment

# Or with an existing plan
./block/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "USGov Virginia" `
    -FunctionAppName "your-func-name" `
    -FirewallPolicyName "your-policy" `
    -FirewallName "your-firewall" `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -ClientSecret "your-client-secret" `
    -BlocklistUrl "https://your-blocklist-url" `
    -AppServicePlanName "existing-plan-name" `
    -AzureCloud AzureUSGovernment
```

#### Scenario 4: Flex Consumption (Linux, Azure Public only)
**Best for:** New Linux Flex apps in Azure Public. Creates a **new** Flex app (not an in-place Classic migrate). One app per Flex plan. PowerShell 7.6 only. For private storage, combine Flex with Scenario 5 or 6. The subscription must have `Microsoft.App` registered (`Get-AzResourceProvider` / `Register-AzResourceProvider`). Classic does not need this.

```powershell
./block/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "eastus" `
    -FunctionAppName "your-func-name-flex" `
    -FirewallPolicyName "your-policy" `
    -FirewallName "your-firewall" `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -ClientSecret "your-client-secret" `
    -BlocklistUrl "https://your-blocklist-url" `
    -HostingPlan FlexConsumption `
    -FlexInstanceMemoryMB 512
```

`-FlexInstanceMemoryMB 512` is optional because 512 MB is the Blocklist default.

After deploy, the script restarts the app and verifies the `blocklist` function is registered (with retries). Rerun the deployment to enable HTTP/2 on an existing Function App; Microsoft Defender may take time to reassess the resource.

#### Scenario 5: Existing secured storage account
**Best for:** Storage already locked down (private endpoints + public access disabled). Deploy uses that account as-is and only VNet-integrates the Function App.

The VNet and integration subnet must already exist. Classic requires `Microsoft.Web/serverFarms` delegation; Flex requires `Microsoft.App/environments` and a registered `Microsoft.App` resource provider. Classic (including Azure Government) does not need `Microsoft.App`.

```powershell
./block/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "USGov Virginia" `
    -FunctionAppName "your-func-name" `
    -FirewallPolicyName "your-policy" `
    -FirewallName "your-firewall" `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -ClientSecret "your-client-secret" `
    -BlocklistUrl "https://your-blocklist-url" `
    -AzureCloud AzureUSGovernment `
    -StorageAccountName "yoursecuredstorage" `
    -StorageAccountResourceGroup "your-rg" `
    -VNetName "your-vnet" `
    -VNetResourceGroup "your-rg" `
    -IntegrationSubnetName "appservice-integration-subnet"
```

`-StorageAccountResourceGroup` and `-VNetResourceGroup` are optional when those resources are in `-ResourceGroupName`.

#### Scenario 6: Create and lock storage
**Best for:** New storage that must not be internet-exposed. Pass a VNet, Function App integration subnet, and private-endpoint subnet. Flex publishes the package while the new storage account is still public, then creates blob/file/queue/table private endpoints, private DNS, and VNet integration, and disables public network access. A rerun against private endpoints that already exist re-enables that public endpoint only for the upload, confirms the setting stuck, and locks the account again. Classic creates the private endpoints first and disables public network access before the Kudu upload.

```powershell
./block/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "eastus" `
    -FunctionAppName "your-func-name" `
    -FirewallPolicyName "your-policy" `
    -FirewallName "your-firewall" `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -ClientSecret "your-client-secret" `
    -BlocklistUrl "https://your-blocklist-url" `
    -VNetName "your-vnet" `
    -VNetResourceGroup "your-rg" `
    -IntegrationSubnetName "appservice-integration-subnet" `
    -PrivateEndpointSubnetName "private-endpoints-subnet"
```

`-VNetResourceGroup` is optional when the VNet is in `-ResourceGroupName`.

Requires `Az.Network` and `Az.PrivateDns`. Flex also requires a registered `Microsoft.App` resource provider (`Get-AzResourceProvider` / `Register-AzResourceProvider`); Classic, including Azure Government, does not. Microsoft Defender may take time to reassess the storage account after deploy.

#### Scenario 7: Custom Cloud Endpoints (Advanced)
**Use case:** Custom sovereign cloud configurations

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
    -BlocklistUrl "https://your-blocklist-url" `
    -AuthorityHost "https://login.microsoftonline.us" `
    -ArmEndpoint "https://management.usgovcloudapi.net"
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

5. **Function host fails after secure storage**
   - Confirm the Function App is VNet-integrated to the delegated subnet
   - For create-and-lock, confirm blob/file/queue/table private endpoints and private DNS links exist
   - Classic integration subnets must be delegated to `Microsoft.Web/serverFarms`; Flex uses `Microsoft.App/environments`
   - Flex VNet join also requires `Microsoft.App` registered (`Register-AzResourceProvider -ProviderNamespace Microsoft.App`). Classic does not.

6. **Rule Collection Issues**
   - The function creates both Blackhole (DNAT) and Blocked-IP (Filter) collections
   - Ensure the Azure Firewall Policy supports both collection types
   - Check that rule priorities don't conflict with existing rules

7. **Cross-Cloud Authentication (AADSTS900382)**
   - Ensure `AZURE_CLOUD` or `AZURE_CLOUD_ENVIRONMENT`, or the `AZURE_AUTHORITY_HOST`/`AZURE_ARM_ENDPOINT` overrides are set correctly for your tenant
   - Example for US Gov: set `AZURE_CLOUD=AzureUSGovernment`

8. **Flex / hosting mode errors**
   - Flex + Azure Government: use Classic instead
   - With `-HostingPlan Auto`, an existing named plan selects Classic or Flex from its SKU; a missing named plan still uses the cloud default
   - Classic deploy against a Flex app/plan (or vice versa): use a new Function App name or the matching `-HostingPlan`
   - Flex VNet join 502 mentioning `Microsoft.App`: register the provider (`Register-AzResourceProvider -ProviderNamespace Microsoft.App`) and rerun. Classic does not need this.

9. **Flex plan creation returns HTTP 429 / exclusive lock**
   - Azure can create the plan while returning a transient server-farm lock response
   - The deployment script checks for the created plan and retries lock/throttle responses with exponential backoff
   - If an older script stopped after the plan appeared, rerun the same deployment command; the existing-plan check makes the rerun safe

10. **`Disable-AzContextAutosave` / `Connect-AzAccount` errors in Function App logs**
   - The platform `profile.ps1` calls Az.Accounts, which this app does not install
   - Redeploy with a script that uploads `src/profile.ps1` to overwrite that template

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
    -FunctionAppName "your-func-name" `
    -FirewallPolicyName "your-policy"
```

Cleanup first removes and verifies the Function App so its timer cannot recreate firewall artifacts. It then waits up to 15 minutes for the Firewall Policy and `CeleriumRuleCollectionGroup` provisioning states to become ready, handling deletion races caused by concurrent Azure operations. After Azure confirms the group is absent, cleanup removes and verifies all IP Groups matching `fw-blocklist-*` in the resource group. It also removes the deployment-created default App Service Plan named `<FunctionAppName>-plan`; differently named custom or shared App Service Plans are preserved. Deploy-created storage and private endpoints (tagged `ManagedBy=AzureNetworkFirewallSupport`) are removed; customer-owned storage passed to deploy with `-StorageAccountName` is left in place, as are the prerequisite VNet, subnets, and shared private DNS zones. Cleanup exits with a non-zero status and lists anything it could not confirm as removed.

For sovereign clouds (e.g., US Gov):
```powershell
./block/cleanup.ps1 `
    -ResourceGroupName "your-rg" `
    -FunctionAppName "your-func-name" `
    -FirewallPolicyName "your-policy" `
    -AzureCloud AzureUSGovernment
```

## API Documentation

For API endpoints and usage details, see [API-Reference.md](API-Reference.md).

# Event Hub Syslog Forwarder

Azure Function that processes Azure Event Hub messages containing various log types (Flow Logs, DNS Queries, DNS Responses, Firewall Logs) and forwards them to a syslog server over SSL or UDP.

## Features

- **Multi-Log Type Support**: Process Virtual Network Flow Logs, Azure Firewall DNS Query Logs, DNS Response Logs, and Firewall Network/Application Rules Logs
- **Batch Processing**: Send multiple messages over a single SSL/TCP connection for improved performance
- **Configurable Timeouts**: Prevent hangs with configurable connection and I/O timeouts
- **Retry with Exponential Backoff**: Automatically retry failed transmissions with configurable backoff
- **Robust Timestamp Handling**: Flexible timestamp resolution that handles multiple record formats (PSCustomObject and Hashtable)
- **Protocol Support**: SSL/TLS or UDP for syslog transmission
- **Secure Function endpoint**: Deployment enforces HTTPS-only access, TLS 1.2, and HTTP/2
- **Cloud-aware hosting default**: `-HostingPlan Auto` infers Classic or Flex from an existing named plan; without one, it uses Linux Flex Consumption in Azure Public and Windows Basic B1 in Azure Government
- **Explicit hosting modes**: Classic works in both clouds; Flex Consumption is available only in Azure Public
- **Optional secure storage**: Use an existing locked-down storage account, or let deploy create private endpoints and disable public access. Both paths VNet-integrate the Function App
- **Comprehensive Error Handling**: Detailed error logging without failing the entire function

## Prerequisites

- Azure subscription
- Existing Event Hub namespace and Event Hub
- PowerShell 7.4 or later
- Azure PowerShell modules:
  - Az.Accounts
  - Az.Resources
  - Az.Storage
  - Az.Functions
  - Az.EventHub
  - Az.ApplicationInsights
  - Az.Network and Az.PrivateDns (only for secure-storage deploy/cleanup)
- App Service Plan (optional; the cloud-aware default creates Flex Consumption in Azure Public or Basic B1 in Azure Government)
- To target an existing plan, pass its name and Auto will infer the hosting mode. Explicit `-HostingPlan Classic` or `FlexConsumption` remains available. Changing between Classic and Flex requires a new Function App. Flex is **not supported** with `-AzureCloud AzureUSGovernment`.

## Supported Log Types

| Log Type | Detection | Description |
|----------|-----------|-------------|
| **Flow Logs** | `SubType = "FlowLog"` | Virtual Network Flow Logs from NSGs. Flows where `SrcNic` or `DestNic` is `unknown-rg/unknown-nic` are ignored (Azure Firewall internal traffic). |
| **DNS Query Logs** | `category = "AZFWDnsQuery"` | Azure Firewall DNS Query Logs |
| **DNS Response Logs** | `category = "DnsResponse"` | Azure Firewall DNS Response Logs |
| **Firewall Logs** | Default | Azure Firewall Network/Application Rules Logs |

## Configuration

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `SYSLOG_SERVER` | Syslog server hostname or IP address |
| `SYSLOG_PORT` | Syslog server port |
| `SYSLOG_PROTOCOL` | Protocol to use: `SSL` or `UDP` (defaults to SSL) |
| `EVENT_HUB_NAME` | Name of the Event Hub |
| `EVENTHUB_CONNECTION` | Event Hub connection string |

### Optional Environment Variables - Timeouts

| Variable | Default | Description |
|----------|---------|-------------|
| `SYSLOG_CONNECT_TIMEOUT_MS` | 5000 | TCP connection timeout in milliseconds |
| `SYSLOG_IO_TIMEOUT_MS` | 5000 | Read/Write operation timeout in milliseconds |

### Optional Environment Variables - Retry Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SYSLOG_MAX_RETRIES` | 3 | Maximum number of retry attempts on failure |
| `SYSLOG_RETRY_BACKOFF_MS` | 500 | Base delay between retries in milliseconds |
| `SYSLOG_RETRY_BACKOFF_MAX_MS` | 5000 | Maximum delay cap between retries in milliseconds |

### Runtime Environment Variables (Auto-configured)

| Variable | Default | Notes |
|----------|---------|-------|
| `FUNCTIONS_WORKER_RUNTIME` | powershell | **Classic only** (Flex uses `functionAppConfig`) |
| `FUNCTIONS_WORKER_RUNTIME_VERSION` | 7.6 | **Classic only** |
| `WEBSITE_RUN_FROM_PACKAGE` | 0 | **Classic only** (enables in-portal editing) |
| `FUNCTIONS_EXTENSION_VERSION` | ~4 | Classic and Flex |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | Auto-configured | Classic and Flex |
| `APPINSIGHTS_INSTRUMENTATIONKEY` | Auto-configured | Classic and Flex |

> `host.json` sets `managedDependency.enabled = false` (no PowerShell Gallery auto-install). Flex forbids managed dependencies; the forwarder does not need Gallery modules. Deploy overwrites `wwwroot/profile.ps1` with a no-op file so the platform template does not call `Connect-AzAccount -Identity`. `function.json` resolves the hub via `%EVENT_HUB_NAME%`.

## Setup

### NOTE
These commands have been tested via cloud shell

1. Upload the content:
   You will need to copy the PowerShell scripts and eventhub folder with the following layout:
   ```
   - forward/
     - deploy.ps1
     - cleanup.ps1
     - src/
       - function.json
       - host.json
       - profile.ps1
       - run.ps1
   ```

2. Deploy using PowerShell:

## Script parameters

### `deploy.ps1`

#### Required

| Parameter | Description |
|-----------|-------------|
| `-ResourceGroupName` | Resource group for the Function App, storage (when created), Application Insights, and deploy-owned private endpoints. Must already exist. |
| `-Location` | Azure region for new resources (for example `eastus` or `USGov Virginia`). |
| `-FunctionAppName` | Function App name. Also used to derive the default storage account name (`<sanitized-name>storage`, max 24 characters) and the default plan name (`<FunctionAppName>-plan`). |
| `-SyslogServer` | Syslog server hostname or IP. |
| `-SyslogPort` | Syslog server port. |
| `-EventHubName` | Event Hub name (written to `EVENT_HUB_NAME`). |
| `-EventHubConnection` | Event Hub connection string (written to `EVENTHUB_CONNECTION`). Prefer single quotes. |

#### Optional hosting and cloud

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Protocol` | `SSL` | Syslog transport: `SSL` or `UDP`. |
| `-AzureCloud` | `AzurePublicCloud` | `AzurePublicCloud` or `AzureUSGovernment`. Selects ARM login environment and storage DNS suffix (`core.windows.net` vs `core.usgovcloudapi.net`). |
| `-HostingPlan` | `Auto` | `Auto`, `Classic`, or `FlexConsumption`. Auto infers Classic or Flex from an existing named plan; otherwise Flex in Azure Public and Classic in Azure Government. Flex is not available in Azure Government. Classic↔Flex in-place migration is not supported. |
| `-FlexInstanceMemoryMB` | `512` | Flex instance memory: `512`, `2048`, or `4096`. Ignored for Classic. |
| `-AppServicePlanName` | Auto-created `<FunctionAppName>-plan` | Existing plan to use. With `-HostingPlan Auto`, the plan SKU selects Classic or Flex. If Classic and no plan is supplied, Azure Public creates Consumption Y1 and Azure Government creates Basic B1. |
| `-AppServicePlanResourceGroup` | `-ResourceGroupName` | Resource group of `-AppServicePlanName` when the plan lives in another group. |

#### Optional secure storage

VNet and subnets are **customer prerequisites**. Deploy never creates a VNet. Secure paths require `Az.Network` and `Az.PrivateDns`. Consumption (Y1) is rejected because it cannot use regional VNet integration — pass a Basic or Premium plan, or use Flex.

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
| `-AzureCloud` | No | `AzurePublicCloud` | `AzurePublicCloud` or `AzureUSGovernment`. |

Cleanup does not take VNet or storage-name parameters. It deletes deploy-owned storage and `{storage}-{blob\|file\|queue\|table}-pe` private endpoints tagged `ManagedBy=AzureNetworkFirewallSupport`. Customer-owned storage (used with `-StorageAccountName` on deploy), VNets, subnets, and shared private DNS zones are preserved.

## Deployment Scenarios

> **Hosting notes**
> - Default `-HostingPlan` is `Auto`: an existing named plan is inferred from its SKU. Without an existing named plan, Azure Public resolves to `FlexConsumption` and Azure Government resolves to `Classic` with an auto-created Basic B1 plan.
> - Explicit `-HostingPlan Classic` or `-HostingPlan FlexConsumption` overrides Auto inference.
> - Classic targeting an existing Flex app/plan (or the reverse) **throws** with a clear error. Azure does not support in-place Classic↔Flex migration — use a new Function App (and plan) name.
> - When Classic is selected and no plan is supplied, Azure Public creates Consumption Y1 and Azure Government creates Basic B1.
> - Forwarder Flex instances default to 512 MB. Use `-FlexInstanceMemoryMB 2048` or `4096` to override the default.
> - Deployment applies app settings non-interactively for both Classic and Flex.
> - Prefer **single quotes** for `-EventHubConnection` (connection strings contain many `=` and `+` characters).
> - Secure storage is opt-in. See [Optional secure storage](#optional-secure-storage) for the public, existing-account, and create-and-lock parameter combinations.

#### Scenario 1: Simple Azure Public Deployment (Auto-creates Flex Consumption Plan)

```powershell
# Deploy with the cloud-aware default
./forward/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "eastus" `
    -FunctionAppName "your-func-name" `
    -SyslogServer "syslog.example.com" `
    -SyslogPort 514 `
    -EventHubName "your-eventhub" `
    -EventHubConnection 'your-connection-string' `
    -Protocol SSL
```

#### Scenario 2: Use Existing App Service Plan

```powershell
# First, find existing App Service Plans in your subscription
Get-AzAppServicePlan | Select-Object Name, ResourceGroup, Sku

# Deploy using an existing plan (Premium, Basic, etc.)
./forward/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "eastus" `
    -FunctionAppName "your-func-name" `
    -SyslogServer "syslog.example.com" `
    -SyslogPort 514 `
    -EventHubName "your-eventhub" `
    -EventHubConnection 'your-connection-string' `
    -Protocol SSL `
    -AppServicePlanName "existing-plan-name" `
    -AppServicePlanResourceGroup "plan-rg"  # Optional, defaults to same RG
```

With `-HostingPlan Auto`, the existing plan's SKU selects Classic or Flex. Pass an explicit hosting mode when you want to require one rather than infer it.

#### Scenario 3: Azure US Government Cloud (Classic only)

> Flex Consumption is **not** available in Azure Government. Do not pass `-HostingPlan FlexConsumption` with `-AzureCloud AzureUSGovernment` (the script throws a clear error).

```powershell
# With auto-created Basic B1 plan
./forward/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "USGov Virginia" `
    -FunctionAppName "your-func-name" `
    -SyslogServer "syslog.example.com" `
    -SyslogPort 514 `
    -EventHubName "your-eventhub" `
    -EventHubConnection 'your-connection-string' `
    -Protocol SSL `
    -AzureCloud AzureUSGovernment

# Or with an existing Windows plan (e.g. Basic B1)
./forward/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "USGov Virginia" `
    -FunctionAppName "your-func-name" `
    -SyslogServer "syslog.example.com" `
    -SyslogPort 514 `
    -EventHubName "your-eventhub" `
    -EventHubConnection 'your-connection-string' `
    -Protocol SSL `
    -AppServicePlanName "existing-plan-name" `
    -AzureCloud AzureUSGovernment
```

#### Scenario 4: Flex Consumption (Linux, Azure Public only)
**Best for:** New Linux Flex apps in Azure Public. Creates a **new** Flex app (not an in-place Classic migrate). One app per Flex plan. PowerShell 7.6 only. For private storage, combine Flex with Scenario 5 or 6. The subscription must have `Microsoft.App` registered (`Get-AzResourceProvider` / `Register-AzResourceProvider`). Classic does not need this.

```powershell
./forward/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "eastus" `
    -FunctionAppName "your-func-name-flex" `
    -SyslogServer "syslog.example.com" `
    -SyslogPort 514 `
    -EventHubName "your-eventhub" `
    -EventHubConnection 'your-connection-string' `
    -Protocol SSL `
    -HostingPlan FlexConsumption `
    -FlexInstanceMemoryMB 512
```

`-FlexInstanceMemoryMB 512` is optional because 512 MB is the Forwarder default.

#### Scenario 5: Existing secured storage account
**Best for:** Storage already locked down (private endpoints + public access disabled). Deploy uses that account as-is and only VNet-integrates the Function App.

The VNet and integration subnet must already exist. Classic requires `Microsoft.Web/serverFarms` delegation; Flex requires `Microsoft.App/environments` and a registered `Microsoft.App` resource provider. Classic (including Azure Government) does not need `Microsoft.App`. Consumption (Y1) does not support VNet integration — pass a Basic or Premium plan, or use Flex.

```powershell
./forward/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "USGov Virginia" `
    -FunctionAppName "your-func-name" `
    -SyslogServer "syslog.example.com" `
    -SyslogPort 514 `
    -EventHubName "your-eventhub" `
    -EventHubConnection 'your-connection-string' `
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
./forward/deploy.ps1 `
    -ResourceGroupName "your-rg" `
    -Location "eastus" `
    -FunctionAppName "your-func-name" `
    -SyslogServer "syslog.example.com" `
    -SyslogPort 514 `
    -EventHubName "your-eventhub" `
    -EventHubConnection 'your-connection-string' `
    -VNetName "your-vnet" `
    -VNetResourceGroup "your-rg" `
    -IntegrationSubnetName "appservice-integration-subnet" `
    -PrivateEndpointSubnetName "private-endpoints-subnet"
```

`-VNetResourceGroup` is optional when the VNet is in `-ResourceGroupName`.

Requires `Az.Network` and `Az.PrivateDns`. Flex also requires a registered `Microsoft.App` resource provider (`Get-AzResourceProvider` / `Register-AzResourceProvider`); Classic, including Azure Government, does not. Microsoft Defender may take time to reassess the storage account after deploy.

The deployment script will:
1. Verify Azure connection and resource group (cloud-aware)
2. Resolve storage: public (default), existing locked account, or create-and-lock with private endpoints
3. Create or update Application Insights
4. Create the resolved hosting plan and Function App (Flex FC1 in Azure Public by default; Classic Basic B1 in Azure Government; Classic Public without a plan still uses Y1 unless a secure-storage path is selected)
5. Enable system-assigned managed identity (Defender for Cloud recommendation)
6. Enforce HTTPS-only access, TLS 1.2, and HTTP/2
7. When secure storage is selected, VNet-integrate the Function App. Classic create-and-lock creates private endpoints before the app and locks storage before upload. Flex create-and-lock publishes first, then creates private endpoints, VNet-integrates, and locks storage
8. Configure runtime settings and environment variables (Flex skips classic `FUNCTIONS_WORKER_RUNTIME*` / `WEBSITE_RUN_FROM_PACKAGE`)
9. Deploy function code (Kudu VFS for Classic; OneDeploy for Flex). Flex create-and-lock uploads while storage is public. If private endpoints already exist, deploy re-enables the public endpoint, checks that Azure kept it enabled, repairs the deployments container URL if needed, retries the Azure CLI upload, and falls back to SCM OneDeploy
10. Restart the function app
11. Verify `EventHubTrigger` is registered and required app settings exist (retries; can take ~2 minutes on Basic/Gov)

> **Note:** Enabling the system-assigned identity clears the Defender recommendation. Event Hub access still uses `EVENTHUB_CONNECTION` until a later managed-identity auth migration.
>
> Rerun the deployment to enable HTTP/2 on an existing Function App. Microsoft Defender may take time to reassess the resource.

### Deployment Validation
The script performs several validation steps:
1. Resource group existence
2. Storage account naming / cloud endpoint suffix
3. Classic vs Flex plan/app compatibility (fails loudly on mismatches)
4. Function code deploy success (Kudu or OneDeploy)
5. Post-deploy: `EventHubTrigger` listed and `EVENTHUB_CONNECTION` / `EVENT_HUB_NAME` / related settings present

## Architecture

### Message Processing Flow

```
Event Hub → Azure Function → Log Type Detection → Format Syslog Message → Batch Send to Syslog Server
```

### Performance Optimizations

1. **Connection Reuse**: All messages from a single Event Hub batch are sent over one SSL/TCP connection instead of opening a new connection per message.

2. **Batch Processing**: Messages are collected and sent in batches, reducing network overhead.

3. **Async Connect with Timeout**: Uses non-blocking connection with configurable timeout to prevent function hangs.

### Resilience Features

1. **Retry with Exponential Backoff**: Failed transmissions are automatically retried with increasing delays.

2. **Graceful Degradation**: Syslog transmission failures are logged but don't cause the function to fail, preventing message loss in Event Hub.

3. **Robust Timestamp Resolution**: Handles multiple timestamp field formats and falls back to current UTC time if no timestamp is found.

## Error Handling and Monitoring

### Error Handling
The function includes comprehensive error handling:
- Input validation for required environment variables
- Connection timeout handling
- Retry logic with exponential backoff
- Detailed error logging
- Non-blocking error handling (syslog failures don't crash the function)

### Monitoring
Monitor the function using:
- Azure Portal > Function App > Functions > EventHubTrigger > Monitor
- Application Insights logs and metrics
- Function execution logs

### Common Issues

| Issue | Possible Cause | Solution |
|-------|---------------|----------|
| Connection timeout | Syslog server unreachable | Check network connectivity, firewall rules |
| SSL handshake failure | Certificate issues | Verify syslog server certificate |
| Messages not arriving | Event Hub binding issue | Check `EVENTHUB_CONNECTION` and `EVENT_HUB_NAME`; confirm `EventHubTrigger` is registered |
| Deploy: no functions registered | Host still indexing, or list API lag (esp. Basic/Gov) | Re-run with updated script (retries); check Kudu `wwwroot/EventHubTrigger` and that Classic plan is Windows |
| Flex plan create returns HTTP 429 / exclusive lock | Transient App Service server-farm lock; Azure may still create the plan | The script rechecks the plan and retries with backoff. If an older script stopped after the plan appeared, rerun the same command safely |
| Flex zip deploy: `BlobUploadFailedException` / "The specified resource does not exist" | The deployment service uploads the package from outside the VNet. Storage that already has private endpoints and public access disabled returns 404 for that upload | Rerun the updated script. A new Flex create-and-lock publishes before private endpoints exist. A rerun re-enables public access, confirms Azure kept `publicNetworkAccess=Enabled` and `defaultAction=Allow`, repairs the deployments container URL if needed, then locks the account again |
| Flex deploy in Gov | Flex not available in Azure Government | Omit `-HostingPlan` to use the Auto B1 default, or pass `-HostingPlan Classic` |
| Existing named plan selects the wrong mode | The plan was not found in `-AppServicePlanResourceGroup`, or an explicit mode was supplied | Verify the plan resource group and use `-HostingPlan Auto` to infer its SKU |
| Classic deploy hits Flex plan/app | Wrong hosting mode for existing resources | Use a new app/plan name for Classic, or pass `-HostingPlan FlexConsumption` |
| Function timeout | Too many messages | Increase timeout or reduce batch size |
| Function host fails after secure storage | Missing VNet integration, private DNS, or queue/blob private endpoints | Confirm the app is VNet-integrated; create-and-lock needs blob/file/queue/table PEs. Consumption (Y1) cannot use this path. Flex also needs `Microsoft.App` registered |
| Flex VNet join returns 502 / Microsoft.App | `Microsoft.App` is not registered in the subscription | Run `Register-AzResourceProvider -ProviderNamespace Microsoft.App`, wait until Registered, then rerun deploy. Classic does not need this |
| `Disable-AzContextAutosave` / `Connect-AzAccount` in logs | Platform `profile.ps1` calls Az.Accounts, which is not installed | Redeploy so `src/profile.ps1` overwrites `wwwroot/profile.ps1` |

### Troubleshooting Steps

1. Check function logs in Azure Portal:
   - Go to Function App > Functions > EventHubTrigger > Monitor
   - Or use Azure CLI:
```powershell
az functionapp logs tail `
    --name "your-func-name" `
    --resource-group "your-rg"
```

2. Verify environment variables:
   - Check SYSLOG_SERVER and SYSLOG_PORT are correct
   - Validate Event Hub connection string

3. Test network connectivity:
   - Verify syslog server is reachable from Azure
   - Check any firewall or NSG rules

4. Increase timeouts if needed:
   - Set `SYSLOG_CONNECT_TIMEOUT_MS` and `SYSLOG_IO_TIMEOUT_MS` to higher values

## Syslog Message Formats

### Flow Log Format
```
<13>TimeGenerated={timestamp} Type=FlowLog FaSchemaVersion={version} 
    TimeProcessed={timestamp} FlowIntervalStart={timestamp} FlowIntervalEnd={timestamp}
    FlowStartTime={timestamp} FlowEndTime={timestamp} FlowType={type}
    SrcIp={ip} DstIp={ip} DstPort={port} Protocol={protocol} L7Protocol={protocol}
    Direction={direction} Status={status} SrcNic={nic} DestNic={nic}
    BytesDestToSrc={bytes} BytesSrcToDest={bytes}
    ...
```

### DNS Query Log Format
```
<13>TimeGenerated={timestamp} Type=DnsQueryLog 
    ResourceId={id} SrcIp={ip} SrcPort={port} QueryId={id}
    QueryType={type} QueryClass={class} QueryName={name} Protocol={protocol}
    RequestSize={size} ResponseCode={code} ResponseSize={size}
    ...
```

### DNS Response Log Format
```
<13>TimeGenerated={timestamp} Type=DnsResponseLog 
    ResourceId={id} QueryName={name} QueryType={type} ResponseCode={code}
    SrcIpAddr={ip} SrcPort={port} DstIpAddr={ip} DstPort={port}
    DnsAnswerIndex={index} DnsAnswerType={type} DnsAnswerRData={data}
    ...
```

### Firewall Log Format
```
<13>TimeGenerated={timestamp} Type=FirewallLog 
    ResourceId={id} Protocol={protocol} SrcIp={ip} SrcPort={port}
    DstIp={ip} DstPort={port} Action={action}
    Policy={policy} RuleCollectionGroup={group} RuleCollection={collection}
    Rule={rule} ActionReason={reason}
```

## Cleanup

Remove all deployed resources:
```powershell
./forward/cleanup.ps1 `
    -ResourceGroupName "your-rg" `
    -FunctionAppName "your-func-name"
```

Cleanup also removes the deployment-created default App Service Plan named `<FunctionAppName>-plan` after confirming no other sites use it. Differently named custom or shared plans are preserved. Deploy-created storage and private endpoints (tagged `ManagedBy=AzureNetworkFirewallSupport`) are removed; customer-owned storage passed to deploy with `-StorageAccountName` is left in place, as are the prerequisite VNet, subnets, and shared private DNS zones.

For sovereign clouds (e.g., US Gov):
```powershell
./forward/cleanup.ps1 `
    -ResourceGroupName "your-rg" `
    -FunctionAppName "your-func-name" `
    -AzureCloud AzureUSGovernment
```

## Version History

### v2.0.0 (Current)
- Added batch sending over single SSL connection for improved performance
- Added configurable connection and I/O timeouts
- Added retry logic with exponential backoff
- Added robust timestamp resolution for multiple record formats
- Improved error handling and logging

### v1.0.0
- Initial release with basic syslog forwarding

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
- **Comprehensive Error Handling**: Detailed error logging without failing the entire function

## Prerequisites

- Azure subscription
- Existing Event Hub namespace and Event Hub
- PowerShell 7.4
- Azure PowerShell modules:
  - Az.Accounts
  - Az.Resources
  - Az.Storage
  - Az.Functions
  - Az.EventHub
  - Az.ApplicationInsights
- App Service Plan (optional; the cloud-aware default creates Flex Consumption in Azure Public or Basic B1 in Azure Government)
- To target an existing plan, pass its name and Auto will infer the hosting mode. Explicit `-HostingPlan Classic` or `FlexConsumption` remains available. Changing between Classic and Flex requires a new Function App. Flex is **not supported** with `-AzureCloud AzureUSGovernment`.

## Supported Log Types

| Log Type | Detection | Description |
|----------|-----------|-------------|
| **Flow Logs** | `SubType = "FlowLog"` | Virtual Network Flow Logs from NSGs |
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
| `FUNCTIONS_WORKER_RUNTIME_VERSION` | 7.4 | **Classic only** |
| `WEBSITE_RUN_FROM_PACKAGE` | 0 | **Classic only** (enables in-portal editing) |
| `FUNCTIONS_EXTENSION_VERSION` | ~4 | Classic and Flex |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | Auto-configured | Classic and Flex |
| `APPINSIGHTS_INSTRUMENTATIONKEY` | Auto-configured | Classic and Flex |

> `host.json` sets `managedDependency.enabled = false` (no PowerShell Gallery auto-install). Flex forbids managed dependencies; the forwarder does not need Gallery modules. `function.json` resolves the hub via `%EVENT_HUB_NAME%`.

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
       - run.ps1
   ```

2. Deploy using PowerShell:

### Deployment Scenarios

> **Hosting notes**
> - Default `-HostingPlan` is `Auto`: an existing named plan is inferred from its SKU. Without an existing named plan, Azure Public resolves to `FlexConsumption` and Azure Government resolves to `Classic` with an auto-created Basic B1 plan.
> - Explicit `-HostingPlan Classic` or `-HostingPlan FlexConsumption` overrides Auto inference.
> - Classic targeting an existing Flex app/plan (or the reverse) **throws** with a clear error. Azure does not support in-place Classic↔Flex migration — use a new Function App (and plan) name.
> - When Classic is selected and no plan is supplied, Azure Public creates Consumption Y1 and Azure Government creates Basic B1.
> - Forwarder Flex instances default to 512 MB. Use `-FlexInstanceMemoryMB 2048` or `4096` to override the default.
> - Deployment applies app settings non-interactively for both Classic and Flex.
> - Prefer **single quotes** for `-EventHubConnection` (connection strings contain many `=` and `+` characters).

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
**Best for:** Secure storage / VNet scenarios. Creates a **new** Linux Flex app (not an in-place Classic migrate). One app per Flex plan. PowerShell 7.4 only.

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

The deployment script will:
1. Verify Azure connection and resource group (cloud-aware)
2. Create or update storage account (auto-named from function app name)
3. Create or update Application Insights
4. Create the resolved hosting plan and Function App (Flex FC1 in Azure Public by default; Classic Basic B1 in Azure Government)
5. Enable system-assigned managed identity (Defender for Cloud recommendation)
6. Enforce HTTPS-only access, TLS 1.2, and HTTP/2
7. Configure runtime settings and environment variables (Flex skips classic `FUNCTIONS_WORKER_RUNTIME*` / `WEBSITE_RUN_FROM_PACKAGE`)
8. Deploy function code (Kudu VFS for Classic; OneDeploy `/api/publish?type=zip` or Azure CLI for Flex)
9. Restart the function app
10. Verify `EventHubTrigger` is registered and required app settings exist (retries; can take ~2 minutes on Basic/Gov)

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
| Flex deploy in Gov | Flex not available in Azure Government | Omit `-HostingPlan` to use the Auto B1 default, or pass `-HostingPlan Classic` |
| Existing named plan selects the wrong mode | The plan was not found in `-AppServicePlanResourceGroup`, or an explicit mode was supplied | Verify the plan resource group and use `-HostingPlan Auto` to infer its SKU |
| Classic deploy hits Flex plan/app | Wrong hosting mode for existing resources | Use a new app/plan name for Classic, or pass `-HostingPlan FlexConsumption` |
| Function timeout | Too many messages | Increase timeout or reduce batch size |

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
    Direction={direction} Status={status} BytesDestToSrc={bytes} BytesSrcToDest={bytes}
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

Cleanup also removes the deployment-created default App Service Plan named `<FunctionAppName>-plan` after confirming no other sites use it. Differently named custom or shared plans are preserved.

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

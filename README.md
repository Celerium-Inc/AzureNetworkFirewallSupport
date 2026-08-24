# Azure Security Tools

A collection of Azure security and monitoring tools designed to enhance your Azure infrastructure security posture.

## Hosting

Both Function App projects support:

- **Cloud-aware default (`-HostingPlan Auto`)** — infer Classic or Flex when an existing plan name is supplied; otherwise use Linux Flex Consumption in Azure Public or Windows Basic B1 in Azure Government.
- **Explicit Classic** — pass `-HostingPlan Classic` for a Windows Consumption / Basic / existing App Service Plan
- **Explicit Flex Consumption** — pass `-HostingPlan FlexConsumption` for a Linux Flex plan (Azure Public only; not available in Azure Government). Changing between Classic and Flex requires a new Function App.
- **Flex sizing** — both projects default to 512 MB and support explicit 2048 MB or 4096 MB overrides.
- **System-assigned managed identity** — enabled on deploy (Defender for Cloud). Runtime Event Hub / Firewall auth still uses connection strings or service principal until a later migration.

See each project's README for deploy parameters and scenarios.

## Projects

### 1. Azure Firewall Blocklist Integration
PowerShell-based Azure Function that automatically updates Azure Firewall IP Groups with blocklists from external sources. This solution provides continuous protection with no security gaps during updates.

**Key Features:**
- Continuous protection with no security gaps during updates
- Intelligent IP distribution across multiple groups
- Optimized performance with batched operations
- Enhanced reliability with comprehensive error handling
- Extended timeout handling for Azure Firewall operations
- Automated updates with configurable schedules (default: every 10 minutes)
- RESTful API endpoints for testing and manual operations
- Classic or Flex hosting; system-assigned managed identity on deploy

**Technical Highlights:**
- Efficiently handles large IP sets (up to 50,000+ IPs)
- Smart IP group management (up to 5,000 IPs per group)
- Comprehensive logging and monitoring
- Secure service principal authentication for Firewall/IP Group APIs
- Graceful handling of Azure API timeouts

[View Documentation](Blocklist%20Integration/README.md)

### 2. Event Hub Syslog Forwarder
Azure Function that forwards Event Hub messages to a Syslog server over SSL/UDP. Processes various Azure log types including Flow Logs, DNS Queries, DNS Responses, and Firewall Logs.

**Key Features:**
- Secure log forwarding (SSL/TLS and UDP)
- Multiple log type support:
  - Virtual Network Flow Logs
  - Azure Firewall DNS Query Logs
  - Azure Firewall DNS Response Logs
  - Azure Firewall Network/Application Rules Logs
- Configurable syslog formatting
- Detailed error handling
- Classic (Public + Gov) or Flex (Public only); post-deploy verification of `EventHubTrigger`

[View Documentation](Event%20Hub%20Syslog%20Forwarder/README.md)

## Repository Structure

```
├── Blocklist Integration/         # IP Blocklist Manager
│   ├── src/                     # Source code directory
│   ├── README.md                # Implementation details
│   └── API-Reference.md         # Technical API documentation
├── Event Hub Syslog Forwarder/   # Syslog Forwarder
│   ├── src/                     # Source code directory
│   └── README.md                # Implementation details
└── README.md                    # Repository overview
```

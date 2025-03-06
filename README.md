# Azure Security Tools

A collection of Azure security and monitoring tools.

## Projects

### 1. Azure Firewall IP Blocklist Manager

PowerShell-based Azure Function for managing IP blocklists in Azure Firewall. This solution provides automated updates and management of blocked IP addresses through a RESTful API.

[View Project Details](Blocklist%20Integration/README.md)

### 2. Event Hub Syslog Forwarder

Azure Function that forwards Event Hub messages to a Syslog server over SSL/UDP. Processes various Azure log types including Flow Logs, DNS Queries, DNS Responses, and Firewall Logs.

#### Features
- Secure log forwarding via SSL/TLS or UDP
- Support for multiple log types:
  - Virtual Network Flow Logs
  - Azure Firewall DNS Query Logs
  - Azure Firewall DNS Response Logs
  - Azure Firewall Network/Application Rules Logs
- Configurable syslog formatting
- Detailed error handling and logging

## Repository Structure

```
├── Blocklist Integration/         # IP Blocklist Manager
│   ├── src/                      # Function source code
│   │   ├── run.ps1              # Main function script
│   │   ├── function.json        # Function configuration
│   │   ├── host.json            # Function host settings
│   │   └── requirements.psd1    # PowerShell dependencies
│   ├── deploy.ps1               # Deployment script
│   ├── cleanup.ps1              # Resource cleanup script
│   ├── README.md                # Function documentation
│   ├── API-Reference.md         # API documentation
│   └── Setup.md                 # Detailed setup guide
├── Event Hub Syslog Forwarder/   # Syslog Forwarder
│   ├── src/                     # Source code directory
│   │   ├── forward-logs.ps1     # SSL/TLS implementation
│   │   └── forward-logs-using-udp.ps1  # UDP implementation
│   └── README.md                # Project documentation
└── README.md                    # Repository overview
```

## Prerequisites

1. Azure Resources:
   - Azure subscription
   - Resource group
   - Azure Function Apps
   - Event Hub (for Syslog Forwarder)
   - Azure Firewall and Policy (for IP Blocklist)

2. Development Requirements:
   - PowerShell 7.2 or later
   - Azure PowerShell module
   - Azure CLI (optional)
   - Syslog server (for Syslog Forwarder)

## Quick Links

- [IP Blocklist Manager Setup](Blocklist%20Integration/Setup.md)
- [IP Blocklist API Reference](Blocklist%20Integration/API-Reference.md)
- [Syslog Forwarder Documentation](Event%20Hub%20Syslog%20Forwarder/README.md)
# Azure Security Tools

A collection of Azure security and monitoring tools designed to enhance your Azure infrastructure security posture.

## Projects

### 1. Azure Firewall IP Blocklist Manager
PowerShell-based Azure Function for managing IP blocklists in Azure Firewall. This solution provides automated updates and management of blocked IP addresses through a RESTful API.

**Key Features:**
- Automated IP blocklist management
- Real-time Azure Firewall policy updates
- Support for large IP lists with automatic splitting
- Comprehensive monitoring and logging
- Secure service principal authentication
- Custom role-based access control

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

[View Documentation](Event%20Hub%20Syslog%20Forwarder/README.md)

## Repository Structure

```
├── Blocklist Integration/         # IP Blocklist Manager
│   ├── src/                      # Function source code
│   ├── deploy.ps1               # Deployment script
│   ├── cleanup.ps1              # Resource cleanup script
│   └── README.md                # Implementation details
├── Event Hub Syslog Forwarder/   # Syslog Forwarder
│   ├── src/                     # Source code directory
│   └── README.md                # Implementation details
└── README.md                    # Repository overview
```

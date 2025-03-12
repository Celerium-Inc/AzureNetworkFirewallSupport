# Azure Network Firewall Support

A collection of Azure security tools designed to enhance your Azure Firewall infrastructure with advanced security features and monitoring capabilities.

## Components

### 1. Azure Firewall IP Blocklist Integration
PowerShell-based Azure Function that manages IP blocklists in Azure Firewall, providing automated updates and management of blocked IP addresses through a RESTful API.

**Key Features:**
- Automated IP blocklist management with external source integration
- Real-time Azure Firewall policy updates
- Support for large IP lists with automatic group splitting
- Custom role-based access control (RBAC)
- Secure service principal authentication
- Comprehensive monitoring and logging

[View Documentation](Blocklist%20Integration/README.md)

### 2. Event Hub Syslog Forwarder
Azure Function that forwards Azure Event Hub messages to a Syslog server over SSL/UDP, supporting various Azure log types including Flow Logs, DNS Queries, DNS Responses, and Firewall Logs.

**Key Features:**
- Dual protocol support:
  - SSL/TLS for secure transmission
  - UDP for high-performance scenarios
- Multiple log type processing:
  - Virtual Network Flow Logs
  - Azure Firewall DNS Query Logs
  - Azure Firewall DNS Response Logs
  - Azure Firewall Network/Application Rules Logs
- Configurable syslog formatting
- High-volume log processing with batching
- Comprehensive error handling and retry logic

[View Documentation](Event%20Hub%20Syslog%20Forwarder/README.md)

## Repository Structure

```
├── Blocklist Integration/           # IP Blocklist Manager
│   ├── src/                        # Function source code
│   ├── deploy.ps1                  # Deployment script
│   ├── cleanup.ps1                 # Resource cleanup script
│   ├── README.md                   # Implementation details
│   ├── Setup.md                    # Setup instructions
│   └── API-Reference.md            # API documentation
├── Event Hub Syslog Forwarder/     # Syslog Forwarder
│   ├── src/                        # Source code directory
│   ├── deploy.ps1                  # Deployment script
│   ├── cleanup.ps1                 # Resource cleanup script
│   └── README.md                   # Implementation details
└── README.md                       # Repository overview
```

## Prerequisites

- Azure subscription
- PowerShell 7.2 or later
- Azure PowerShell modules:
  - Az.Accounts
  - Az.Resources
  - Az.Storage
  - Az.Functions
  - Az.Network (for Blocklist Integration)
  - Az.EventHub (for Syslog Forwarder)

## Quick Start

  Choose your component:
   - For IP Blocklist Integration: [Setup Guide](Blocklist%20Integration/Setup.md)
   - For Event Hub Syslog Forwarder: [Setup Guide](Event%20Hub%20Syslog%20Forwarder/README.md)

## Documentation

- [Blocklist Integration](Blocklist%20Integration/README.md)
  - [Setup Guide](Blocklist%20Integration/Setup.md)
  - [API Reference](Blocklist%20Integration/API-Reference.md)

- [Event Hub Syslog Forwarder](Event%20Hub%20Syslog%20Forwarder/README.md)
  - Deployment and configuration
  - Log format specifications
  - Protocol details
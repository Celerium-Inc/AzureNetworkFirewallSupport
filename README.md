# Azure Security Tools

A collection of Azure security and monitoring tools designed to enhance your Azure infrastructure security posture.

## Projects

### 1. Azure Firewall Blocklist Integration
PowerShell-based Azure Function that automatically updates Azure Firewall IP Groups with blocklists from external sources. This solution provides continuous protection with no security gaps during updates.

**Key Features:**
- Continuous protection with no security gaps during updates
- Intelligent IP distribution across multiple groups
- Optimized performance with batched operations
- Enhanced reliability with comprehensive error handling
- Extended timeout handling for Azure Firewall operations
- Automated updates with configurable schedules
- RESTful API endpoints for testing and manual operations

**Technical Highlights:**
- Efficiently handles large IP sets (up to 50,000+ IPs)
- Smart IP group management (up to 5,000 IPs per group)
- Configurable update frequency (default: every 10 minutes)
- Comprehensive logging and monitoring
- Secure service principal authentication
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

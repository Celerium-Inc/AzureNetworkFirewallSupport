# Azure Network Firewall Support

Collection of Azure Functions for managing Azure Firewall configurations and logs. This project provides automated solutions for IP blocklist management and log forwarding.

## Project Structure

```
AzureNetworkFirewallSupport/
├── Event Hub Syslog Forwarder/          # Event Hub to Syslog forwarding
│   ├── src/
│   │   ├── forward-logs.ps1             # Main log forwarding script (SSL)
│   │   └── forward-logs-using-udp.ps1   # Alternative UDP implementation
│   └── README.md                        # Forwarder documentation
│
├── Blocklist Integration/               # Firewall blocklist management
│   ├── run.ps1                          # Main function script
│   ├── function.json                    # Function configuration
│   ├── requirements.psd1                # PowerShell module requirements
│   ├── .env.example                     # Environment variables template
│   ├── deploy.ps1                       # Quick deployment script
│   ├── README.md                        # Deployment guide
│   └── Overview.md                      # Technical documentation
│
└── README.md                            # Project overview
```

## Quick Deploy

### Blocklist Integration
To quickly deploy the Blocklist Integration function to Azure:

1. Clone this repository
2. Navigate to the Blocklist Integration directory
3. Run the deployment script:
   ```powershell
   ./deploy.ps1 -ResourceGroupName "your-rg-name" `
                -Location "eastus" `
                -FunctionAppName "your-function-name"
   ```

The script will:
- Create necessary Azure resources
- Set up service principal with required permissions
- Deploy the function app
- Configure initial settings

After deployment, you'll need to:
1. Configure your firewall name and policy
2. Set up your blocklist URL
3. Test the deployment

For detailed setup, see the [Blocklist Integration Guide](Blocklist%20Integration/README.md).

## Features

1. **Blocklist Integration**
   - Automated IP blocklist management
   - Real-time Azure Firewall policy updates
   - Support for large IP lists (up to 8000 IPs)
   - Configurable rule priorities and collections
   - Test mode for validation
   - Documentation: [Blocklist Integration](Blocklist%20Integration/README.md)

2. **Event Hub Syslog Forwarder**
   - Secure log forwarding via SSL/TLS
   - Support for multiple log types:
     - Virtual Network Flow Logs
     - Azure Firewall DNS Query Logs
     - Azure Firewall DNS Response Logs
     - Azure Firewall Network/Application Rules Logs
   - Configurable syslog formatting
   - Documentation: [Event Hub Syslog Forwarder](Event%20Hub%20Syslog%20Forwarder/README.md)

## Prerequisites

1. Azure Resources:
   - Azure subscription with appropriate permissions
   - Azure Function App (PowerShell runtime)
   - Azure Firewall and Firewall Policy
   - Event Hub (for log forwarding)
   - Storage Account (for Function Apps)

2. Tools and Access:
   - Azure CLI or Azure PowerShell
   - Azure Functions Core Tools (for deployment)
   - Appropriate RBAC permissions
   - Blocklist URL (for IP management)

## Getting Started

1. Clone this repository

2. Choose your function:
   - For IP blocklist management: [Blocklist Integration Guide](Blocklist%20Integration/README.md)
   - For log forwarding: [Event Hub Forwarder Guide](Event%20Hub%20Syslog%20Forwarder/README.md)

3. Follow the function-specific setup instructions in their respective README files

## Configuration

Each function has its own configuration requirements and environment variables template. See the respective function's documentation for details:
- Blocklist Integration: See `.env.example` in the Blocklist Integration directory
- Event Hub Forwarder: See configuration section in its README

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

See individual function READMEs for specific contribution guidelines.

## Troubleshooting

Common issues and solutions are documented in each function's documentation:
- [Blocklist Integration Troubleshooting](Blocklist%20Integration/OVERVIEW.md#troubleshooting)
- [Event Hub Forwarder Troubleshooting](Event%20Hub%20Syslog%20Forwarder/README.md#troubleshooting)

## Support

For issues and support:
1. Check the function-specific documentation
2. Review Azure Function logs
3. Check Azure Firewall activity logs
4. Submit an issue in the repository 
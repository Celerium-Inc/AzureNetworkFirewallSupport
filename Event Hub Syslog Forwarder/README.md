# Event Hub Syslog Forwarder

Azure Function that forwards Event Hub messages to a Syslog server over SSL. This function processes various Azure log types including Flow Logs, DNS Queries, DNS Responses, and Firewall Logs.

## Features

- Secure log forwarding via SSL/TLS
- Support for multiple log types:
  - Virtual Network Flow Logs
  - Azure Firewall DNS Query Logs
  - Azure Firewall DNS Response Logs
  - Azure Firewall Network/Application Rules Logs
- Configurable syslog formatting
- Detailed error handling and logging

## Prerequisites

- Azure Function App (PowerShell runtime)
- Event Hub namespace and Event Hub
- Syslog server with SSL/TLS support
- Network connectivity between Function App and Syslog server

## Setup

1. Create an Azure Function App:
   ```powershell
   az functionapp create \
     --name <function-app-name> \
     --resource-group <resource-group> \
     --runtime powershell \
     --runtime-version 7.2 \
     --functions-version 4 \
     --os-type Windows
   ```

2. Configure environment variables:
   ```powershell
   az functionapp config appsettings set \
     --name <function-app-name> \
     --resource-group <resource-group> \
     --settings \
       SYSLOG_SERVER=your-syslog-server \
       SYSLOG_PORT=your-syslog-port
   ```

3. Deploy the function:
   ```powershell
   func azure functionapp publish <function-app-name>
   ```

## Configuration

Required environment variables:
- `SYSLOG_SERVER`: Hostname/IP of your syslog server
- `SYSLOG_PORT`: Port number for syslog server

Optional environment variables:
- `LOG_LEVEL`: Logging verbosity (Debug, Information, Warning, Error)
- `SSL_VERIFY_CERT`: Whether to verify SSL certificates (true/false)

The function will fail to start if required environment variables are not set.

## Log Types and Formatting

### 1. Flow Logs
- Traffic flows through Network Security Groups
- Includes source/destination IPs, ports, protocols
- Flow timing and status information

### 2. DNS Query Logs
- DNS queries processed by Azure Firewall
- Query details (name, type, class)
- Response information

### 3. DNS Response Logs
- Detailed DNS response information
- Answer records
- Resolution paths and policies

### 4. Firewall Logs
- Traffic allowed/denied by firewall rules
- Rule collection and policy information
- Connection details

## Protocol Support
- SSL/TLS (secure) - Use `forward-logs.ps1`
- UDP (faster, less secure) - Use `forward-logs-using-udp.ps1`

## Environment Variables
| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| SYSLOG_SERVER | Yes | Hostname/IP of syslog server | - |
| SYSLOG_PORT | Yes | Port number for syslog server | - |
| LOG_LEVEL | No | Logging verbosity (Debug, Information, Warning, Error) | Information |
| SSL_VERIFY_CERT | No | Whether to verify SSL certificates | true |

## Log Format
All logs are formatted as key-value pairs with the following structure:
```
<priority>TimeGenerated=timestamp Type=logtype field1=value1 field2=value2 ...
```

### Supported Log Types
1. Flow Logs (Type=FlowLog)
2. DNS Query Logs (Type=DnsQueryLog)
3. DNS Response Logs (Type=DnsResponseLog)
4. Firewall Logs (Type=FirewallLog)

## Troubleshooting

1. Check function logs:
   ```powershell
   az functionapp logs tail \
     --name <function-app-name> \
     --resource-group <resource-group>
   ```

2. Common issues:
   - Missing environment variables
   - SSL/TLS certificate issues
   - Network connectivity problems
   - Event Hub trigger configuration

## Monitoring

Monitor the function using:
- Azure Application Insights
- Function execution logs
- Syslog server logs

## Support

For issues:
1. Check function execution logs
2. Verify environment variables
3. Test network connectivity
4. Review SSL/TLS configuration 
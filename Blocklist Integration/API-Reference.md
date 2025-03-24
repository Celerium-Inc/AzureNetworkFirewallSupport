# API Reference

## Base URL
```
https://<function-app-name>.azurewebsites.net/api/blocklist
```

## Authentication
All requests require a function key as the `code` query parameter:
```
?code=<function-key>
```

## Endpoints

### Test Connection (`action=test`)
Tests connectivity to Azure resources.

```http
GET /api/blocklist?action=test&code={function_key}
```

#### Process Flow
1. Authenticates with Azure using provided credentials
2. Attempts to list existing IP Groups matching the base name pattern
3. Attempts to retrieve the Rule Collection Group configuration
4. Returns detailed status of each component

#### What It Checks
- Azure authentication
- IP Groups access permissions
- Firewall Policy access permissions
- Resource Group access
- Current configuration state

#### Example Response
```json
{
    "status": "success",
    "message": "Successfully connected to Azure Firewall resources",
    "timestamp": "2024-03-05T18:28:15Z",
    "details": {
        "ipGroups": [
            {
                "name": "fw-blocklist-001",
                "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/your-rg/providers/Microsoft.Network/ipGroups/fw-blocklist-001",
                "type": "Microsoft.Network/ipGroups",
                "location": "eastus",
                "properties": {
                    "ipAddresses": [
                        "1.1.1.1/32",
                        "2.2.2.2/32"
                    ],
                    "provisioningState": "Succeeded"
                }
            }
        ],
        "ruleCollectionGroup": {
            "name": "CeleriumRuleCollectionGroup",
            "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/your-rg/providers/Microsoft.Network/firewallPolicies/your-policy/ruleCollectionGroups/CeleriumRuleCollectionGroup",
            "type": "Microsoft.Network/firewallPolicies/ruleCollectionGroups",
            "priority": 100,
            "ruleCollections": [
                {
                    "name": "Blocked-IP-Collection",
                    "priority": 100,
                    "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
                    "action": {
                        "type": "Deny"
                    },
                    "rules": [
                        {
                            "name": "blocked-IPs-outbound",
                            "ruleType": "NetworkRule",
                            "ipProtocols": ["Any"],
                            "sourceAddresses": ["*"],
                            "destinationIpGroups": [
                                "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/your-rg/providers/Microsoft.Network/ipGroups/fw-blocklist-001"
                            ],
                            "destinationPorts": ["*"]
                        },
                        {
                            "name": "blocked-IPs-inbound",
                            "ruleType": "NetworkRule",
                            "ipProtocols": ["Any"],
                            "sourceIpGroups": [
                                "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/your-rg/providers/Microsoft.Network/ipGroups/fw-blocklist-001"
                            ],
                            "destinationAddresses": ["*"],
                            "destinationPorts": ["*"]
                        }
                    ]
                }
            ]
        },
        "resourceGroup": "your-rg",
        "policyName": "your-policy"
    }
}
```

### Update Blocklist (`action=update`)
Updates firewall rules with latest IPs from configured blocklist URL.

```http
GET /api/blocklist?action=update&code={function_key}
```

#### Process Flow
1. Fetches IP list from configured blocklist URL
2. Validates each IP address
3. Splits IPs into groups (respecting MAX_IPS_PER_GROUP limit)
4. Creates or updates IP Groups for each batch
5. Updates Firewall Policy rules to use these IP Groups
6. Creates both inbound and outbound blocking rules

#### IP Processing
- Strips CIDR notation if present
- Validates IP format
- Adds /32 CIDR notation if missing
- Respects configured limits:
  - MAX_TOTAL_IPS
  - MAX_IPS_PER_GROUP
  - MAX_IP_GROUPS

#### IP Group Mapping
1. **Group Naming**
   - Base name: `fw-blocklist` (configurable)
   - Numbered sequentially: `fw-blocklist-001`, `fw-blocklist-002`, etc.
   - Maximum groups determined by MAX_IP_GROUPS setting

2. **IP Distribution**
   ```
   Example with 12,000 IPs:
   MAX_IPS_PER_GROUP = 5000
   MAX_IP_GROUPS = 10

   Result:
   fw-blocklist-001: 5000 IPs
   fw-blocklist-002: 5000 IPs
   fw-blocklist-003: 2000 IPs
   ```

3. **Rule Collection Mapping**
   ```json
   {
     "ruleCollections": [
       {
         "name": "Blocked-IP-Collection",
         "priority": 100,
         "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
         "action": { "type": "Deny" },
         "rules": [
           {
             "name": "blocked-IPs-outbound",
             "ruleType": "NetworkRule",
             "ipProtocols": ["Any"],
             "sourceAddresses": ["*"],
             "destinationIpGroups": [
               "/subscriptions/.../ipGroups/fw-blocklist-001",
               "/subscriptions/.../ipGroups/fw-blocklist-002",
               "/subscriptions/.../ipGroups/fw-blocklist-003"
             ],
             "destinationPorts": ["*"]
           },
           {
             "name": "blocked-IPs-inbound",
             "ruleType": "NetworkRule",
             "ipProtocols": ["Any"],
             "sourceIpGroups": [
               "/subscriptions/.../ipGroups/fw-blocklist-001",
               "/subscriptions/.../ipGroups/fw-blocklist-002",
               "/subscriptions/.../ipGroups/fw-blocklist-003"
             ],
             "destinationAddresses": ["*"],
             "destinationPorts": ["*"]
           }
         ]
       }
     ]
   }
   ```

4. **Update Process**
   - Existing groups are updated in place if possible
   - New groups are created if needed
   - Empty groups are automatically deleted
   - Updates are atomic within each group
   - Rule Collection is updated only after all groups are ready

#### Example Response
```json
{
    "status": "success",
    "message": "Firewall policy updated successfully",
    "timestamp": "2024-03-05T18:28:15Z",
    "details": {
        "ipGroupIds": [
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/your-rg/providers/Microsoft.Network/ipGroups/fw-blocklist-001",
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/your-rg/providers/Microsoft.Network/ipGroups/fw-blocklist-002"
        ],
        "ruleCollectionGroup": {
            "name": "CeleriumRuleCollectionGroup",
            "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/your-rg/providers/Microsoft.Network/firewallPolicies/your-policy/ruleCollectionGroups/CeleriumRuleCollectionGroup",
            "priority": 100,
            "ruleCollections": [
                {
                    "name": "Blocked-IP-Collection",
                    "priority": 100,
                    "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
                    "action": {
                        "type": "Deny"
                    },
                    "rules": [
                        {
                            "name": "blocked-IPs-outbound",
                            "ruleType": "NetworkRule",
                            "ipProtocols": ["Any"],
                            "sourceAddresses": ["*"],
                            "destinationIpGroups": [
                                "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/your-rg/providers/Microsoft.Network/ipGroups/fw-blocklist-001",
                                "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/your-rg/providers/Microsoft.Network/ipGroups/fw-blocklist-002"
                            ],
                            "destinationPorts": ["*"]
                        },
                        {
                            "name": "blocked-IPs-inbound",
                            "ruleType": "NetworkRule",
                            "ipProtocols": ["Any"],
                            "sourceIpGroups": [
                                "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/your-rg/providers/Microsoft.Network/ipGroups/fw-blocklist-001",
                                "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/your-rg/providers/Microsoft.Network/ipGroups/fw-blocklist-002"
                            ],
                            "destinationAddresses": ["*"],
                            "destinationPorts": ["*"]
                        }
                    ]
                }
            ]
        },
        "totalIpsProcessed": 1000,
        "groupsCreated": 2,
        "ipsPerGroup": [500, 500],
        "requestInfo": {
           "blocklistUrl": "https://url/blocklist/00000000-0000-0000-0000-000000000000",
           "maxTotalIps": 50000,
            "maxIpsPerGroup": 5000,
            "maxIpGroups": 10
        }
    }
}
```

### Unblock IPs (`action=unblock`)
Removes specific IPs from blocklist.

```http
POST /api/blocklist?action=unblock&code={function_key}
Content-Type: application/json
{
    "ips": [
        "1.1.1.1",
        "2.2.2.2"
    ]
}
```

#### Process Flow
1. Receives list of IPs to unblock
2. Validates each IP address
3. Retrieves all existing IP Groups
4. For each IP Group:
   - Checks if it contains any IPs to unblock
   - Removes matching IPs
   - Updates the IP Group if changes were made
5. Updates Firewall Policy rules if needed

#### IP Handling
- Matches IPs with or without CIDR notation
- Maintains original CIDR format for remaining IPs
- Deletes groups that become empty
- Updates all affected groups atomically

#### Example Response
```json
{
    "status": "success",
    "message": "Successfully unblocked IPs",
    "timestamp": "2024-03-05T18:28:15Z",
    "details": {
        "updatedGroups": [
            {
                "id": "/subscriptions/.../ipGroups/fw-blocklist-001",
                "name": "fw-blocklist-001",
                "removedCount": 5,
                "remainingCount": 4495
            }
        ],
        "deletedGroups": [
            {
                "name": "fw-blocklist-002",
                "removedCount": 3200
            }
        ],
        "unblocked": [
            "192.168.1.1",
            "10.0.0.1"
        ]
    }
}
```

## Error Handling

### Common Error Types

#### Authentication Errors
- Invalid credentials
- Expired tokens
- Insufficient permissions

#### Resource Errors
- Resource not found
- Rate limiting
- API version mismatches

#### Data Validation Errors
- Invalid IP addresses
- Missing required parameters
- Exceeded size limits

### Error Response Format
```json
{
    "status": "error",
    "message": "Detailed error description",
    "timestamp": "2024-03-05T18:28:15Z"
}
```

### Status Codes
- 400: Bad Request (invalid parameters)
- 401: Unauthorized (invalid function key)
- 500: Internal Server Error

## Retry Logic

All Azure API calls include built-in retry logic:
- Maximum 5 retries for IP Group operations
- Maximum 3 retries for Rule Collection updates
- Exponential backoff between retries
- Detailed logging of retry attempts 
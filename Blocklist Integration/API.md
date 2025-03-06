# Azure Firewall Blocklist Integration - API Reference

This document describes the API endpoints available in the Azure Firewall Blocklist Integration.

## Base URL

```
https://<function-app-name>.azurewebsites.net/api/blocklist
```

## Authentication

All requests require a function key passed as the `code` query parameter:

```
?code=<function-key>
```

## Endpoints

All endpoints are accessed via HTTP GET requests to `/api/blocklist`. Authentication is done via function key in the `code` query parameter.

### Test Connection
Tests connectivity to Azure resources and validates configuration.

```http
GET /api/blocklist?action=test&code={function_key}
```

#### Response
```json
{
    "status": "success",
    "message": "Successfully connected to Azure Firewall resources",
    "timestamp": "2024-03-05T18:28:15Z",
    "details": {
        "ipGroup": { /* IP Group details */ },
        "ruleCollectionGroup": { /* Rule Collection details */ },
        "resourceGroup": "your-resource-group",
        "policyName": "your-policy-name",
        "requestInfo": {
            "ipGroupUrl": "https://...",
            "ruleCollectionUrl": "https://...",
            "apiVersion": "2024-01-01"
        }
    }
}
```

### Update Blocklist
Fetches IPs from configured blocklist URL and updates Azure Firewall rules.

```http
GET /api/blocklist?action=update&code={function_key}
```

#### Response
```json
{
    "status": "success",
    "message": "Firewall policy updated successfully",
    "timestamp": "2024-03-05T18:28:15Z",
    "details": {
        "ipGroupIds": ["id1", "id2"],
        "ruleCollectionGroup": { /* Rule Collection details */ },
        "totalIpsProcessed": 1000,
        "groupsCreated": 2,
        "ipsPerGroup": [500, 500],
        "requestInfo": {
            "blocklistUrl": "https://...",
            "maxTotalIps": 50000,
            "maxIpsPerGroup": 5000,
            "maxIpGroups": 10
        }
    }
}
```

### Unblock IPs
Removes specific IPs from the blocklist.

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

#### Response
```json
{
    "status": "success",
    "message": "Successfully unblocked IPs",
    "timestamp": "2024-03-05T18:28:15Z",
    "details": {
        "ipGroupId": "group-id",
        "ruleCollectionGroup": { /* Rule Collection details */ },
        "unblocked": ["1.1.1.1", "2.2.2.2"],
        "requestInfo": {
            "providedIps": ["1.1.1.1", "2.2.2.2"],
            "validIps": ["1.1.1.1", "2.2.2.2"],
            "invalidCount": 0
        }
    }
}
```

## Error Responses

All errors follow this format:
```json
{
    "status": "error",
    "message": "Error description",
    "timestamp": "2024-03-05T18:28:15Z"
}
```

Common error status codes:
- 400: Bad Request (invalid parameters)
- 401: Unauthorized (invalid function key)
- 500: Internal Server Error (Azure API or processing errors)

## CORS Support

The API supports CORS for these origins:
- https://portal.azure.com
- https://ms.portal.azure.com
- https://functions.azure.com

## Rate Limiting

No explicit rate limiting is implemented, but consider:
- Azure Functions consumption plan limits
- Azure Firewall API limits
- Network bandwidth constraints

## Best Practices

1. Always check response status codes
2. Implement retry logic for failed requests
3. Handle errors gracefully
4. Monitor API usage and response times
5. Keep function keys secure 
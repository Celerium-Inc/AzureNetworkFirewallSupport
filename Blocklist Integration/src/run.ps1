# Azure Firewall Blocklist Integration Function
# This function manages IP blocklists in Azure Firewall using IP Groups and Rule Collection Groups.
# Features:
# - Testing connectivity to Azure resources
# - Updating blocklist from external source
# - Unblocking specific IPs
# - Both inbound and outbound blocking rules

using namespace System.Net

# Input bindings are passed in via param block
param(
    [Parameter(Mandatory = $true)]
    $Request,            # HTTP request object containing query parameters and body
    $TriggerMetadata    # Azure Functions runtime metadata
)

# Required environment variables
$subscriptionId = $env:SUBSCRIPTION_ID
$resourceGroup = $env:RESOURCE_GROUP
$firewallName = $env:FIREWALL_NAME
$policyName = $env:POLICY_NAME
$blocklistUrl = $env:BLKLIST_URL

# Optional configuration with defaults
$maxTotalIps = [int]($env:MAX_TOTAL_IPS ?? 50000)
$maxIpsPerGroup = [int]($env:MAX_IPS_PER_GROUP ?? 5000)
$maxIpGroups = [int]($env:MAX_IP_GROUPS ?? 10)
$baseIpGroupName = $env:BASE_IP_GROUP_NAME ?? "fw-blocklist"
$ruleCollectionGroupName = $env:RULE_COLLECTION_GROUP_NAME ?? "CeleriumRuleCollectionGroup"
$ruleCollectionName = $env:RULE_COLLECTION_NAME ?? "Blocked-IP-Collection"
$rulePriority = [int]($env:RULE_PRIORITY ?? 100)

# Set logging verbosity (1=Basic, 2=Verbose)
$global:LogVerbosity = [int]($env:LOG_VERBOSITY ?? 2)  # Default to verbose logging

# Error handling preference
$ErrorActionPreference = 'Stop'

# Cache IP regex pattern for performance
$script:ipRegex = [regex]'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'

# Add at start of script
$script:jsonSettings = [Newtonsoft.Json.JsonSerializerSettings]@{
    TypeNameHandling = 'None'
    MaxDepth = 10
}

# Global API version for all Azure REST API calls
$script:apiVersion = "2024-01-01"

# Logging function with verbosity levels
function Write-FunctionLog {
    param(
        [string]$Message,
        [ValidateSet("Information", "Warning", "Error", "Verbose")]
        [string]$Level = "Information"
    )

    try {
        # Only write verbose logs if verbosity level is high enough
        $shouldWrite = switch ($Level) {
            "Verbose" { $global:LogVerbosity -ge 2 }
            default { $true }  # Always write Info/Warning/Error
        }

        if ($shouldWrite) {
            $color = switch ($Level) {
                "Error" { "Red" }
                "Warning" { "Yellow" }
                "Verbose" { "Cyan" }
                default { "White" }
            }
            Write-Host "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") [$Level] $Message" -ForegroundColor $color
        }
    }
    catch {
        $errorRecord = $_
        $errorMessage = $errorRecord.Exception.Message

        # Fallback to basic Write-Host if something goes wrong
        Write-Host "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") [ERROR] Logging failed: $errorMessage"
        Write-Host "Original message: $Message"
    }
}

# IP address validation with CIDR support
function Test-IpAddress {
    param([string]$IpAddress)

    # Strip CIDR notation if present
    $ip = $IpAddress -replace '/\d+$', ''

    # Use cached regex and avoid double parsing
    if (-not $script:ipRegex.IsMatch($ip)) { return $false }

    try {
        $parts = $ip.Split('.')
        return $parts.Count -eq 4 -and $parts.ForEach{
            [int]$_ -ge 0 -and [int]$_ -le 255
        }
    }
    catch {
        return $false
    }
}

# Fetches and validates IP addresses from the blocklist URL
function Get-BlocklistIps {
    param([string]$Url)
    try {
        # Stream response instead of loading all at once
        $request = [System.Net.WebRequest]::Create($Url)
        $response = $request.GetResponse()
        $reader = [System.IO.StreamReader]::new($response.GetResponseStream())

        $ipList = [System.Collections.ArrayList]@()
        while (-not $reader.EndOfStream -and $ipList.Count -lt $maxTotalIps) {
            $line = $reader.ReadLine()
            if ($line -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' -and (Test-IpAddress $line)) {
                [void]$ipList.Add($line)
            }
        }

        $reader.Close()
        $response.Close()

        return $ipList
    }
    catch {
        throw "Failed to fetch blocklist: $_"
    }
}

# Add function to split IPs into groups
function Split-IpsIntoGroups {
    param(
        [array]$IpList,
        [int]$MaxIpsPerGroup,
        [int]$MaxGroups
    )

    Write-FunctionLog "Splitting $($IpList.Count) IPs into groups" -Level "Verbose"
    
    $groups = @()
    $totalGroups = [Math]::Min([Math]::Ceiling($IpList.Count / $MaxIpsPerGroup), $MaxGroups)

    for ($i = 0; $i -lt $totalGroups; $i++) {
        $startIndex = $i * $MaxIpsPerGroup
        $endIndex = [Math]::Min(($i + 1) * $MaxIpsPerGroup - 1, $IpList.Count - 1)

        if ($startIndex -lt $IpList.Count) {
            $groupIps = @($IpList[$startIndex..$endIndex])
            Write-FunctionLog "Created group $($i + 1) with $($groupIps.Count) IPs" -Level "Verbose"
            $groups += ,$groupIps
        }
    }

    return $groups
}

# Simplified Update-IpGroup function
function Update-IpGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroup,
        [Parameter(Mandatory = $false)]
        [string]$Location = $null,
        [Parameter(Mandatory = $true)]
        [array]$IpAddresses,
        [Parameter(Mandatory = $true)]
        [string]$IpGroupName
    )

    try {
        # Validate we have IPs to process
        if (-not $IpAddresses -or $IpAddresses.Count -eq 0) {
            throw "No IP addresses provided to update IP group"
        }

        Write-FunctionLog "Updating IP Group '$IpGroupName' with $($IpAddresses.Count) IPs"
        Write-FunctionLog "First few IPs: $($IpAddresses[0..([Math]::Min(4, $IpAddresses.Count-1))])" -Level "Verbose"

        # Format IPs with CIDR notation if not already formatted
        $formattedIps = $IpAddresses | ForEach-Object {
            if ($_ -match '/\d+$') { $_ } else { "$_/32" }
        }

        $baseUrl = "https://management.azure.com"
        $ipGroupApiVersion = "2024-07-01"  # Updated to a supported API version
        $url = "$baseUrl/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Network/ipGroups/$IpGroupName"

        # Get location only if not provided
        if (-not $Location) {
            Write-FunctionLog "Getting location for IP Group..." -Level "Verbose"
            try {
                # Try to get existing IP Group first
                $existingGroup = Invoke-RestMethod -Method Get -Uri "$url`?api-version=$ipGroupApiVersion" `
                    -Headers @{ "Authorization" = "Bearer $Token" } `
                    -ErrorAction Stop
                $Location = $existingGroup.location
                Write-FunctionLog "Using existing IP Group location: $Location" -Level "Verbose"
            }
            catch {
                # If IP Group doesn't exist, get location from resource group
                if ($_.Exception.Response.StatusCode.value__ -eq 404) {
                    Write-FunctionLog "IP Group not found, getting location from resource group..." -Level "Verbose"
                    $rgUrl = "$baseUrl/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
                    $rg = Invoke-RestMethod -Method Get -Uri "$rgUrl`?api-version=2024-07-01" `
                        -Headers @{ "Authorization" = "Bearer $Token" } `
                        -ErrorAction Stop
                    $Location = $rg.location
                    Write-FunctionLog "Using resource group location: $Location" -Level "Verbose"
                }
                else {
                    Write-FunctionLog "Failed to get IP Group: $_" -Level "Error"
                    throw
                }
            }
        }

        # Validate location is not null
        if (-not $Location) {
            throw "Unable to determine location for IP Group"
        }

        $body = @{
            location = $Location
            properties = @{
                ipAddresses = $formattedIps
            }
        }

        Write-FunctionLog "Request URL: $url" -Level "Verbose"
        Write-FunctionLog "Request body: $($body | ConvertTo-Json -Depth 10)" -Level "Verbose"

        # Make API call with retries
        $result = Invoke-RestMethod -Method Put -Uri "$url`?api-version=$ipGroupApiVersion" `
            -Headers @{
                "Authorization" = "Bearer $Token"
                "Content-Type" = "application/json"
            } `
            -Body ($body | ConvertTo-Json -Compress -Depth 10) `
            -ContentType "application/json"

        Write-FunctionLog "IP Group update successful" -Level "Verbose"
        return $result
    }
    catch {
        $errorDetails = ""
        try {
            $errorDetails = $_.ErrorDetails.Message
            if (-not $errorDetails) {
                $rawError = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($rawError)
                $errorDetails = $reader.ReadToEnd()
                $reader.Close()
            }
        }
        catch {
            $errorDetails = $_.Exception.Message
        }

        Write-FunctionLog "Update-IpGroup failed with details: $errorDetails" -Level "Error"
        throw "Failed to update IP Group: $errorDetails"
    }
}

# Function to write error responses
function Write-ErrorResponse {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [int]$StatusCode = [HttpStatusCode]::InternalServerError
    )

    # Don't write error to avoid double response
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode
        Body = @{
            status = 'error'
            message = $Message
            timestamp = Get-Date -Format 'o'
        } | ConvertTo-Json
        ContentType = "application/json"
    })
}

# Update firewall rules with IP groups
function Update-RuleCollectionGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroup,
        [Parameter(Mandatory = $true)]
        [string]$FirewallPolicyName,
        [Parameter(Mandatory = $false)]
        [string[]]$IpGroupIds = @()
    )

    $baseUrl = "https://management.azure.com"
    $url = "$baseUrl/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Network/firewallPolicies/$FirewallPolicyName/ruleCollectionGroups/$ruleCollectionGroupName"

    # Modify the body to handle empty IpGroupIds
    $body = @{
        properties = @{
            priority = $rulePriority
            ruleCollections = @(
                @{
                    ruleCollectionType = "FirewallPolicyFilterRuleCollection"
                    action = @{ type = "Deny" }
                    rules = @()  # Always use empty array instead of null
                    name = $ruleCollectionName
                    priority = $rulePriority
                }
            )
        }
    }

    # Only add rules if we have IP groups
    if ($IpGroupIds.Count -gt 0) {
        $body.properties.ruleCollections[0].rules = @(
            @{
                ruleType = "NetworkRule"
                name = "blocked-IPs-outbound"
                ipProtocols = @("Any")
                sourceAddresses = @("*")
                destinationIpGroups = $IpGroupIds
                destinationPorts = @("*")
            },
            @{
                ruleType = "NetworkRule"
                name = "blocked-IPs-inbound"
                ipProtocols = @("Any")
                sourceIpGroups = $IpGroupIds
                destinationAddresses = @("*")
                destinationPorts = @("*")
            }
        )
    }

    Write-FunctionLog "Making request to: $url" -Level "Verbose"
    Write-FunctionLog "Request body: $($body | ConvertTo-Json -Depth 10)" -Level "Verbose"

    return Invoke-RestMethod -Method Put -Uri "$url`?api-version=2024-07-01" `
        -Headers @{
            "Authorization" = "Bearer $Token"
            "Content-Type" = "application/json"
        } `
        -Body ($body | ConvertTo-Json -Compress -Depth 10)
}

# Write success responses in consistent format
function Write-SuccessResponse {
    param(
        [string]$Message,
        [object]$Details = $null
    )

    $response = @{
        status = 'success'
        message = $Message
        timestamp = Get-Date -Format 'o'
    }
    if ($Details) { $response.details = $Details }

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body = $response | ConvertTo-Json -Compress -Depth 10
        ContentType = "application/json"
    })
}

# Make Azure REST API calls with retry logic
function Invoke-AzureRestMethod {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $true)]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        [Parameter(Mandatory = $false)]
        [string]$Body,
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        [Parameter(Mandatory = $false)]
        [int]$RetryDelay = 5,
        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = $script:apiVersion
    )

    $attempt = 1
    while ($attempt -le $MaxRetries) {
        try {
            Write-FunctionLog "API Request Attempt $attempt of $MaxRetries to $Uri" -Level "Verbose"

            if ($attempt -gt 1) {
                $delay = $RetryDelay * [Math]::Pow(2, ($attempt - 1))
                Write-FunctionLog "Waiting $delay seconds before retry..." -Level "Warning"
                Start-Sleep -Seconds $delay
            }

            if ($Body) {
                $result = Invoke-RestMethod -Method $Method -Uri "$Uri`?api-version=$ApiVersion" -Headers $Headers -Body $Body -ContentType "application/json"
            }
            else {
                $result = Invoke-RestMethod -Method $Method -Uri "$Uri`?api-version=$ApiVersion" -Headers $Headers
            }

            return $result
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            $errorMessage = $_.ErrorDetails.Message

            Write-FunctionLog "API request failed (Attempt $attempt): Status $statusCode - $errorMessage" -Level "Warning"

            if ($attempt -eq $MaxRetries) {
                Write-FunctionLog "Max retries reached. Failing operation." -Level "Error"
                throw
            }

            $attempt++
        }
    }
}

function Invoke-TestAction {
    param(
        [string]$Token,
        [hashtable]$Headers
    )

    Write-FunctionLog "Starting test action..."

    # Log key variables for debugging
    Write-FunctionLog "Using configuration:"
    Write-FunctionLog "- Subscription: $subscriptionId"
    Write-FunctionLog "- Resource Group: $resourceGroup"
    Write-FunctionLog "- Policy Name: $policyName"
    Write-FunctionLog "- Base IP Group Name: $baseIpGroupName"

    # Test IP Groups
    $ipGroupsUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Network/ipGroups"

    Write-FunctionLog "Testing IP Groups access..."
    Write-FunctionLog "Request URL: $ipGroupsUrl"

    try {
        $ipGroups = Invoke-AzureRestMethod -Method Get `
            -Uri $ipGroupsUrl `
            -Headers $Headers `
            -MaxRetries 3 `
            -RetryDelay 5 `
            -ApiVersion "2024-07-01"

        $blockedIpGroups = $ipGroups.value | Where-Object { $_.name -like "$baseIpGroupName-*" }
        
        Write-FunctionLog "Found $($blockedIpGroups.Count) IP Groups matching pattern '$baseIpGroupName-*'"
        foreach ($group in $blockedIpGroups) {
            Write-FunctionLog "- $($group.name): $($group.properties.ipAddresses.Count) IPs" -Level "Verbose"
        }
    }
    catch {
        Write-FunctionLog "Failed to list IP Groups: $_" -Level "Warning"
        $blockedIpGroups = $null
    }

    # Test Rule Collection Group
    $ruleCollectionUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Network/firewallPolicies/$policyName/ruleCollectionGroups/$ruleCollectionGroupName"

    Write-FunctionLog "Testing Rule Collection Group access..."
    Write-FunctionLog "Request URL: $ruleCollectionUrl"

    try {
        $ruleCollection = Invoke-AzureRestMethod -Method Get `
            -Uri $ruleCollectionUrl `
            -Headers $Headers `
            -MaxRetries 3 `
            -RetryDelay 5 `
            -ApiVersion $script:apiVersion

        Write-FunctionLog "Successfully retrieved Rule Collection Group"
    }
    catch {
        Write-FunctionLog "Rule Collection Group not found or access denied: $_" -Level "Warning"
        $ruleCollection = $null
    }

    # Return detailed response
    Write-SuccessResponse -Message "Successfully connected to Azure Firewall resources" -Details @{
        ipGroups = if ($blockedIpGroups) { @($blockedIpGroups) } else { @() }  # Convert to array or empty array
        ruleCollectionGroup = $ruleCollection
        resourceGroup = $resourceGroup
        policyName = $policyName
        requestInfo = @{
            ipGroupsUrl = $ipGroupsUrl
            ruleCollectionUrl = $ruleCollectionUrl
            baseIpGroupName = $baseIpGroupName
            firewallApiVersion = $script:apiVersion
            ipGroupApiVersion = "2024-07-01"
        }
    }
}

function Invoke-UpdateAction {
    param([string]$Token)

    Write-FunctionLog "Starting update action..."

    # Get blocklist IPs first
    Write-FunctionLog "Fetching blocklist from URL: $blocklistUrl"
    $blocklistIps = Get-BlocklistIps -Url $blocklistUrl
    Write-FunctionLog "Found $($blocklistIps.Count) IPs in blocklist"

    # Get all existing groups
    Write-FunctionLog "Fetching existing IP groups..."
    $existingGroups = Invoke-AzureRestMethod -Method Get `
        -Uri "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Network/ipGroups" `
        -Headers @{ "Authorization" = "Bearer $Token" } `
        -MaxRetries 3 `
        -RetryDelay 5 `
        -ApiVersion "2024-07-01"
    
    $existingBlocklistGroups = $existingGroups.value | Where-Object { $_.name -like "$baseIpGroupName-*" }
    
    # Split IPs into groups
    $ipGroups = Split-IpsIntoGroups -IpList $blocklistIps -MaxIpsPerGroup $maxIpsPerGroup -MaxGroups $maxIpGroups
    Write-FunctionLog "Need $($ipGroups.Count) groups for current IPs"

    # First, update rule collection to empty state
    Write-FunctionLog "Removing IP group references from rule collection"
    $result = Update-RuleCollectionGroup -Token $Token `
        -SubscriptionId $subscriptionId `
        -ResourceGroup $resourceGroup `
        -FirewallPolicyName $policyName

    # Wait for the rule collection update to complete
    Write-FunctionLog "Waiting for rule collection update to complete..."
    $maxWaitTime = 300 # 5 minutes
    $startTime = Get-Date
    do {
        Start-Sleep -Seconds 10
        $status = Invoke-AzureRestMethod -Method Get `
            -Uri "https://management.azure.com$($result.id)" `
            -Headers @{ "Authorization" = "Bearer $Token" } `
            -ApiVersion "2024-07-01"
        
        if ($status.properties.provisioningState -eq "Succeeded") {
            Write-FunctionLog "Rule collection update completed"
            break
        }
        elseif ($status.properties.provisioningState -eq "Failed") {
            throw "Rule collection update failed"
        }

        if (((Get-Date) - $startTime).TotalSeconds -gt $maxWaitTime) {
            throw "Timeout waiting for rule collection update"
        }

        Write-FunctionLog "Still waiting... Current state: $($status.properties.provisioningState)" -Level "Verbose"
    } while ($true)

    # Update existing groups and create new ones as needed
    $newGroupResults = @()
    $groupsToDelete = [System.Collections.ArrayList]@($existingBlocklistGroups)

    for ($i = 0; $i -lt $ipGroups.Count; $i++) {
        $groupIps = $ipGroups[$i]
        $groupName = "$baseIpGroupName-{0:D3}" -f ($i + 1)
        
        # Check if we can reuse an existing group
        $existingGroup = $existingBlocklistGroups | Where-Object { $_.name -eq $groupName }
        
        if ($existingGroup) {
            Write-FunctionLog "Updating existing group $groupName with $($groupIps.Count) IPs"
            $groupsToDelete.Remove($existingGroup)
        } else {
            Write-FunctionLog "Creating new group $groupName with $($groupIps.Count) IPs"
        }

        $ipGroup = Update-IpGroup -Token $Token `
            -SubscriptionId $subscriptionId `
            -ResourceGroup $resourceGroup `
            -IpAddresses $groupIps `
            -IpGroupName $groupName

        $newGroupResults += @{
            id = $ipGroup.id
            name = $groupName
            count = $groupIps.Count
            isNew = ($null -eq $existingGroup)
        }
    }

    # Delete any remaining unused groups
    if ($groupsToDelete.Count -gt 0) {
        Write-FunctionLog "Deleting $($groupsToDelete.Count) unused groups"
        foreach ($group in $groupsToDelete) {
            Write-FunctionLog "Deleting unused group $($group.name)"
            Remove-IpGroup -Token $Token `
                -SubscriptionId $subscriptionId `
                -ResourceGroup $resourceGroup `
                -IpGroupName $group.name
        }
    }

    # Update firewall policy with all groups
    Write-FunctionLog "Creating new rule collection with IP groups"
    $result = Update-RuleCollectionGroup -Token $Token `
        -SubscriptionId $subscriptionId `
        -ResourceGroup $resourceGroup `
        -FirewallPolicyName $policyName `
        -IpGroupIds ($newGroupResults.id)

    Write-SuccessResponse -Message "Successfully updated IP groups" -Details @{
        groupsCreated = ($newGroupResults | Where-Object { $_.isNew })
        groupsUpdated = ($newGroupResults | Where-Object { -not $_.isNew })
        groupsDeleted = $groupsToDelete | Select-Object name
        totalIps = $blocklistIps.Count
    }
}

# Add new function to delete IP groups
function Remove-IpGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroup,
        [Parameter(Mandatory = $true)]
        [string]$IpGroupName
    )

    try {
        Write-FunctionLog "Deleting IP Group '$IpGroupName'..."
        
        $baseUrl = "https://management.azure.com"
        $url = "$baseUrl/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Network/ipGroups/$IpGroupName"
        
        Invoke-RestMethod -Method Delete -Uri "$url`?api-version=2024-07-01" `
            -Headers @{ "Authorization" = "Bearer $Token" }
        
        Write-FunctionLog "Successfully deleted IP Group '$IpGroupName'"
        return $true
    }
    catch {
        Write-FunctionLog "Failed to delete IP Group '$IpGroupName': $_" -Level "Error"
        throw
    }
}

function Invoke-UnblockAction {
    param(
        [string]$Token,
        [PSCustomObject]$Body
    )

    Write-FunctionLog "Starting unblock action..."
    Write-FunctionLog "Request body type: $($Body.GetType().Name)" -Level "Verbose"
    Write-FunctionLog "Request body: $($Body | ConvertTo-Json)" -Level "Verbose"

    # Get IPs from request body
    if ($Body.ips) {
        $IpsToUnblock = $Body.ips
        Write-FunctionLog "Using IPs from request body: Count = $($IpsToUnblock.Count)"
    }
    else {
        Write-FunctionLog "Missing IPs parameter" -Level "Error"
        Write-ErrorResponse -Message "Missing required 'ips' array in request body" -StatusCode 400
        return
    }

    Write-FunctionLog "Starting IP validation..."
    # Validate IPs and strip CIDR notation
    $validIps = $IpsToUnblock | ForEach-Object {
        $ip = $_ -replace '/\d+$', ''  # Strip CIDR notation
        Write-FunctionLog "Validating IP: $ip" -Level "Verbose"
        if (Test-IpAddress $ip) {
            Write-FunctionLog "IP is valid: $ip" -Level "Verbose"
            $ip
        }
    }
    Write-FunctionLog "IP validation complete. Found $($validIps.Count) valid IPs"

    # Get all IP groups
    Write-FunctionLog "Fetching IP groups..."
    $ipGroupsUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Network/ipGroups"

    try {
        Write-FunctionLog "Making API request to: $ipGroupsUrl"
        $ipGroups = Invoke-AzureRestMethod -Method Get -Uri $ipGroupsUrl `
            -Headers @{ "Authorization" = "Bearer $Token" } `
            -MaxRetries 3 `
            -RetryDelay 5 `
            -ApiVersion "2024-07-01"
        Write-FunctionLog "Successfully retrieved IP groups"

        $blockedIpGroups = $ipGroups.value | Where-Object { $_.name -like "$baseIpGroupName-*" }
        Write-FunctionLog "Found $($blockedIpGroups.Count) matching IP groups"

        foreach ($group in $blockedIpGroups) {
            Write-FunctionLog "Group $($group.name) has $($group.properties.ipAddresses.Count) IPs" -Level "Verbose"
        }
    }
    catch {
        Write-FunctionLog "Failed to list IP Groups: $_" -Level "Error"
        throw
    }

    # Track which groups were updated or deleted
    $updatedGroups = @()
    $deletedGroups = @()
    $unblocked = [System.Collections.ArrayList]@()

    # Process each IP group
    foreach ($group in $blockedIpGroups) {
        Write-FunctionLog "Processing group: $($group.name)" -Level "Verbose"
        
        # Get current IPs both with and without CIDR
        $currentIpsWithCidr = $group.properties.ipAddresses
        $currentIpsWithoutCidr = $currentIpsWithCidr | ForEach-Object { $_ -replace '/32$', '' }
        
        Write-FunctionLog "Current IPs in group (with CIDR): $($currentIpsWithCidr -join ', ')" -Level "Verbose"
        Write-FunctionLog "Current IPs in group (without CIDR): $($currentIpsWithoutCidr -join ', ')" -Level "Verbose"
        Write-FunctionLog "IPs to unblock: $($validIps -join ', ')" -Level "Verbose"

        # Check for matches in both formats
        $ipsToRemove = $validIps | Where-Object {
            $ip = $_
            $isMatch = $ip -in $currentIpsWithoutCidr -or "$ip/32" -in $currentIpsWithCidr
            Write-FunctionLog "Checking IP $ip - Match found: $isMatch" -Level "Verbose"
            $isMatch
        }

        if ($ipsToRemove) {
            Write-FunctionLog "Found $($ipsToRemove.Count) IPs to remove from group $($group.name)"
            Write-FunctionLog "IPs to remove: $($ipsToRemove -join ', ')" -Level "Verbose"

            # Keep original CIDR format for remaining IPs
            $remainingIps = $currentIpsWithCidr | Where-Object {
                $ip = $_
                $shouldKeep = ($_ -replace '/32$', '') -notin $ipsToRemove
                Write-FunctionLog "Checking if IP $ip should be kept: $shouldKeep" -Level "Verbose"
                $shouldKeep
            }
            
            Write-FunctionLog "Remaining IPs after removal: $($remainingIps.Count)" -Level "Verbose"
            Write-FunctionLog "Remaining IPs: $($remainingIps -join ', ')" -Level "Verbose"

            if ($remainingIps.Count -eq 0) {
                Write-FunctionLog "Group would be empty, deleting group $($group.name)" -Level "Warning"
                try {
                    Remove-IpGroup -Token $Token `
                        -SubscriptionId $subscriptionId `
                        -ResourceGroup $resourceGroup `
                        -IpGroupName $group.name

                    $deletedGroups += @{
                        name = $group.name
                        removedCount = $ipsToRemove.Count
                    }
                    [void]$unblocked.AddRange([string[]]@($ipsToRemove))
                }
                catch {
                    Write-FunctionLog "Failed to delete empty group $($group.name): $_" -Level "Error"
                    throw
                }
            }
            else {
                try {
                    Write-FunctionLog "Group object: $($group | ConvertTo-Json)" -Level "Verbose"
                    Write-FunctionLog "Group name: $($group.name)" -Level "Verbose"
                    Write-FunctionLog "Remaining IPs count: $($remainingIps.Count)" -Level "Verbose"

                    $ipGroup = Update-IpGroup -Token $Token `
                        -SubscriptionId $subscriptionId `
                        -ResourceGroup $resourceGroup `
                        -IpAddresses $remainingIps `
                        -IpGroupName $group.name

                    Write-FunctionLog "Updated IP Group $($group.name) with $($remainingIps.Count) IPs" -Level "Verbose"
                    $updatedGroups += @{
                        id = $ipGroup.id
                        name = $group.name
                        removedCount = $ipsToRemove.Count
                        remainingCount = $remainingIps.Count
                    }
                    [void]$unblocked.AddRange([string[]]@($ipsToRemove))
                }
                catch {
                    Write-FunctionLog "Failed to update group $($group.name): $_" -Level "Error"
                    throw
                }
            }
        }
    }

    if ($updatedGroups.Count -eq 0 -and $deletedGroups.Count -eq 0) {
        Write-FunctionLog "No IP Groups needed updating" -Level "Warning"
        Write-SuccessResponse -Message "No IPs found to unblock" -Details @{
            requestInfo = @{
                providedIps = $IpsToUnblock
                validIps = $validIps
            }
        }
        return
    }

    # Get remaining groups after deletions
    $remainingGroups = $blockedIpGroups | Where-Object { $_.name -notin $deletedGroups.name }

    if ($remainingGroups.Count -gt 0) {
        # Update Rule Collection Group with remaining groups
        Write-FunctionLog "Updating Rule Collection Group..."
        $result = Update-RuleCollectionGroup -Token $Token `
            -SubscriptionId $subscriptionId `
            -ResourceGroup $resourceGroup `
            -FirewallPolicyName $policyName `
            -IpGroupIds ($remainingGroups | ForEach-Object { $_.id })
    }
    else {
        Write-FunctionLog "No remaining groups to update in Rule Collection"
        $result = $null
    }

    Write-SuccessResponse -Message "Successfully unblocked IPs" -Details @{
        updatedGroups = $updatedGroups
        deletedGroups = $deletedGroups
        ruleCollectionGroup = $result
        unblocked = $unblocked
        requestInfo = @{
            providedIps = $IpsToUnblock
            validIps = $validIps
            invalidCount = $IpsToUnblock.Count - $validIps.Count
        }
    }
}

# Main execution block
try {
    # Get query parameters
    $action = $Request.Query.action
    if (-not $action) {
        Write-ErrorResponse -Message "Missing required 'action' parameter" -StatusCode 400
        return
    }

    # Authentication block
    try {
        Write-FunctionLog "Getting Azure access token..."
        $tokenUrl = "https://login.microsoftonline.com/$($env:TENANT_ID)/oauth2/v2.0/token"
        $tokenBody = @{
            grant_type = "client_credentials"
            client_id = $env:CLIENT_ID
            client_secret = $env:CLIENT_SECRET
            scope = "https://management.azure.com/.default"
        }

        $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
        if (-not $tokenResponse.access_token) {
            throw "Failed to get valid access token"
        }

        $headers = @{
            "Authorization" = "Bearer $($tokenResponse.access_token)"
            "Content-Type" = "application/json"
        }
        Write-FunctionLog "Successfully obtained access token"
    }
    catch {
        Write-FunctionLog "Authentication failed: $_" -Level "Error"
        Write-ErrorResponse -Message "Failed to authenticate with Azure: $_" -StatusCode 500
        return
    }

    # Process action
    try {
        switch ($action.ToLower()) {
            'test' {
                Invoke-TestAction -Token $tokenResponse.access_token -Headers $headers
            }
            'update' {
                Invoke-UpdateAction -Token $tokenResponse.access_token
            }
            'unblock' {
                Invoke-UnblockAction -Token $tokenResponse.access_token -Body $Request.Body
            }
            default {
                Write-ErrorResponse -Message "Invalid action: $action" -StatusCode 400
            }
        }
    }
    catch {
        $errorRecord = $_
        $errorMessage = $errorRecord.Exception.Message
        $stackTrace = $errorRecord.ScriptStackTrace

        Write-FunctionLog "$action action failed: $errorMessage" -Level "Error"
        Write-FunctionLog "Stack trace: $stackTrace" -Level "Error"

        $statusMessage = switch ($action.ToLower()) {
            'test' { "Test failed" }
            'update' { "Failed to update firewall policy" }
            'unblock' { "Failed to unblock IPs" }
            default { "Action failed" }
        }

        Write-ErrorResponse -Message "$statusMessage - $errorMessage" -StatusCode 500
    }
}
catch {
    Write-FunctionLog "Unhandled error: $_" -Level "Error"
    Write-ErrorResponse -Message "Internal server error: $_" -StatusCode 500
}

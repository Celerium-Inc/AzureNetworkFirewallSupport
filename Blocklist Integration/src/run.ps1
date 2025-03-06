# Azure Firewall Blocklist Integration Function
# This function manages IP blocklists in Azure Firewall using IP Groups and Rule Collection Groups.
# It supports:
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

# Environment variables and constants
$subscriptionId = $env:SUBSCRIPTION_ID
$resourceGroup = $env:RESOURCE_GROUP
$firewallName = $env:FIREWALL_NAME
$policyName = $env:POLICY_NAME
$blocklistUrl = $env:BLKLIST_URL
$maxTotalIps = [int]($env:MAX_TOTAL_IPS ?? 50000)
$maxIpsPerGroup = [int]($env:MAX_IPS_PER_GROUP ?? 5000)
$maxIpGroups = [int]($env:MAX_IP_GROUPS ?? 10)
$baseIpGroupName = $env:BASE_IP_GROUP_NAME ?? "fw-blocklist"

# Set logging verbosity (1=Basic, 2=Verbose)
$global:LogVerbosity = [int]($env:LOG_VERBOSITY ?? 2)  # Default to verbose logging

# Fixed constants - these should not be changed as they're part of the integration
$ruleCollectionGroupName = $env:RULE_COLLECTION_GROUP_NAME ?? "CeleriumRuleCollectionGroup"
$ruleCollectionName = $env:RULE_COLLECTION_NAME ?? "Blocked-IP-Collection"
$rulePriority = [int]($env:RULE_PRIORITY ?? 100)

# At the start of the script, add error handling
$ErrorActionPreference = 'Stop'

# Add more detailed logging with verbosity levels
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
            # Add color coding for different levels
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

# Cache IP regex pattern
$script:ipRegex = [regex]'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'

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
    
    $groups = @()
    $totalGroups = [Math]::Min([Math]::Ceiling($IpList.Count / $MaxIpsPerGroup), $MaxGroups)
    
    for ($i = 0; $i -lt $totalGroups; $i++) {
        $startIndex = $i * $MaxIpsPerGroup
        $endIndex = [Math]::Min(($i + 1) * $MaxIpsPerGroup - 1, $IpList.Count - 1)
        
        if ($startIndex -lt $IpList.Count) {
            $groups += ,@($IpList[$startIndex..$endIndex])
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

        Write-FunctionLog "Formatted first few IPs: $($formattedIps[0..([Math]::Min(4, $formattedIps.Count-1))])" -Level "Verbose"

        $baseUrl = "https://management.azure.com"
        $apiVersion = "2024-01-01"
        $url = "$baseUrl/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Network/ipGroups/$IpGroupName"

        # Try to get existing IP Group first to get location
        try {
            Write-FunctionLog "Getting existing IP Group location..." -Level "Verbose"
            $existingGroup = Invoke-AzureRestMethod -Method Get -Uri "$url`?api-version=$apiVersion" `
                -Headers @{ "Authorization" = "Bearer $Token" }
            $Location = $existingGroup.location
            Write-FunctionLog "Using existing IP Group location: $Location" -Level "Verbose"
        }
        catch {
            # Check if it's a 404 (not found) error
            if ($_.Exception.Response.StatusCode.value__ -eq 404) {
                Write-FunctionLog "IP Group not found, getting location from resource group..." -Level "Verbose"
                $rgUrl = "$baseUrl/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup?api-version=$apiVersion"
                try {
                    $rg = Invoke-AzureRestMethod -Method Get -Uri $rgUrl `
                        -Headers @{ "Authorization" = "Bearer $Token" }
                    $Location = $rg.location
                    Write-FunctionLog "Using resource group location: $Location" -Level "Verbose"
                }
                catch {
                    Write-FunctionLog "Failed to get resource group location: $_" -Level "Error"
                    throw
                }
            }
            else {
                Write-FunctionLog "Failed to get IP Group: $_" -Level "Error"
                throw
            }
        }

        $body = @{
            location = $Location
            properties = @{
                ipAddresses = $formattedIps
            }
        }

        Write-FunctionLog "Request body: $($body | ConvertTo-Json)" -Level "Verbose"

        # Make API call with retries
        $result = Invoke-AzureRestMethod -Method Put -Uri "$url`?api-version=$apiVersion" `
            -Headers @{
                "Authorization" = "Bearer $Token"
                "Content-Type" = "application/json"
            } `
            -Body ($body | ConvertTo-Json -Compress -Depth 10) `
            -MaxRetries 5 `
            -RetryDelay 10

        return $result
    }
    catch {
        Write-FunctionLog "Update-IpGroup failed: $_" -Level "Error"
        throw
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

# Fix Update-RuleCollectionGroup function parameters
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
        [Parameter(Mandatory = $true)]
        [string[]]$IpGroupIds
    )
    
    $baseUrl = "https://management.azure.com"
    $apiVersion = "2024-01-01"
    $url = "$baseUrl/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Network/firewallPolicies/$FirewallPolicyName/ruleCollectionGroups/$ruleCollectionGroupName"
    
    $body = @{
        properties = @{
            priority = $rulePriority
            ruleCollections = @(
                @{
                    ruleCollectionType = "FirewallPolicyFilterRuleCollection"
                    action = @{ type = "Deny" }
                    rules = @(
                        @{
                            ruleType = "NetworkRule"
                            name = "blocked-IPs-outbound"
                            ipProtocols = @("Any")
                            sourceAddresses = @("*")
                            destinationIpGroups = @($IpGroupIds)
                            destinationPorts = @("*")
                        },
                        @{
                            ruleType = "NetworkRule"
                            name = "blocked-IPs-inbound"
                            ipProtocols = @("Any")
                            sourceIpGroups = @($IpGroupIds)
                            destinationAddresses = @("*")
                            destinationPorts = @("*")
                        }
                    )
                    name = $ruleCollectionName
                    priority = $rulePriority
                }
            )
        }
    } | ConvertTo-Json -Compress -Depth 10
    
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type" = "application/json"
    }
    
    return Invoke-AzureRestMethod -Method Put -Uri "$url`?api-version=$apiVersion" `
        -Headers $headers -Body $body -MaxRetries 3 -RetryDelay 5
}

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
        [int]$MaxRetries = 5,         # Increased from 3 to 5
        [Parameter(Mandatory = $false)]
        [int]$RetryDelay = 10         # Increased from 5 to 10 seconds
    )

    $attempt = 1
    while ($attempt -le $MaxRetries) {
        try {
            Write-FunctionLog "API Request Attempt $attempt of $MaxRetries to $Uri"
            
            # Add delay before each retry (except first attempt)
            if ($attempt -gt 1) {
                $delay = $RetryDelay * [Math]::Pow(2, ($attempt - 1))  # Exponential backoff
                Write-FunctionLog "Waiting $delay seconds before retry..." -Level "Warning"
                Start-Sleep -Seconds $delay
            }
            
            if ($Body) {
                $result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -Body $Body
            }
            else {
                $result = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers
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

# Add at start of script
$script:jsonSettings = [Newtonsoft.Json.JsonSerializerSettings]@{
    TypeNameHandling = 'None'
    MaxDepth = 10
}

# Add these functions before the main switch block:

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
    $apiVersion = "2024-01-01"
    $ipGroupsUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Network/ipGroups?api-version=$apiVersion"
    
    Write-FunctionLog "Testing IP Groups access..."
    Write-FunctionLog "Request URL: $ipGroupsUrl"
    
    try {
        $ipGroups = Invoke-RestMethod -Method Get -Uri $ipGroupsUrl -Headers $Headers -ErrorAction Stop
        $blockedIpGroups = $ipGroups.value | Where-Object { $_.name -like "$baseIpGroupName-*" }
        
        if ($blockedIpGroups) {
            Write-FunctionLog "Found $($blockedIpGroups.Count) IP Groups matching pattern '$baseIpGroupName-*'"
            foreach ($group in $blockedIpGroups) {
                Write-FunctionLog "- $($group.name): $($group.properties.ipAddresses.Count) IPs" -Level "Verbose"
            }
        } else {
            Write-FunctionLog "No IP Groups found matching pattern '$baseIpGroupName-*'" -Level "Warning"
        }
    }
    catch {
        Write-FunctionLog "Failed to list IP Groups: $_" -Level "Warning"
        $blockedIpGroups = $null
    }

    # Test Rule Collection Group
    $ruleCollectionUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Network/firewallPolicies/$policyName/ruleCollectionGroups/$ruleCollectionGroupName?api-version=$apiVersion"
    
    Write-FunctionLog "Testing Rule Collection Group access..."
    Write-FunctionLog "Request URL: $ruleCollectionUrl"
    
    try {
        $ruleCollection = Invoke-RestMethod -Method Get -Uri $ruleCollectionUrl -Headers $Headers -ErrorAction Stop
        Write-FunctionLog "Successfully retrieved Rule Collection Group"
    }
    catch {
        Write-FunctionLog "Rule Collection Group not found or access denied: $_" -Level "Warning"
        $ruleCollection = $null
    }

    # Return detailed response
    Write-SuccessResponse -Message "Successfully connected to Azure Firewall resources" -Details @{
        ipGroups = $blockedIpGroups
        ruleCollectionGroup = $ruleCollection
        resourceGroup = $resourceGroup
        policyName = $policyName
        requestInfo = @{
            ipGroupsUrl = $ipGroupsUrl
            ruleCollectionUrl = $ruleCollectionUrl
            apiVersion = $apiVersion
            baseIpGroupName = $baseIpGroupName
        }
    }
}

function Invoke-UpdateAction {
    param(
        [string]$Token
    )
    
    Write-FunctionLog "Starting update action..."
    Write-FunctionLog "Fetching blocklist from URL: $blocklistUrl"

    # Get blocklist IPs
    $blocklistIps = Get-BlocklistIps -Url $blocklistUrl
    Write-FunctionLog "Found $($blocklistIps.Count) IPs in blocklist"

    if ($blocklistIps.Count -eq 0) {
        Write-FunctionLog "No IPs found in blocklist" -Level "Warning"
        Write-SuccessResponse -Message "No blocklist IPs to update"
        return
    }

    # Split IPs into groups
    $ipGroups = Split-IpsIntoGroups -IpList $blocklistIps -MaxIpsPerGroup $maxIpsPerGroup -MaxGroups $maxIpGroups
    Write-FunctionLog "Split IPs into $($ipGroups.Count) groups"

    $ipGroupResults = @()
    
    foreach ($groupIndex in 0..($ipGroups.Count-1)) {
        $groupIps = $ipGroups[$groupIndex]
        $groupName = "$baseIpGroupName-{0:D3}" -f ($groupIndex + 1)
        
        Write-FunctionLog "Processing group $($groupIndex + 1) of $($ipGroups.Count) with $($groupIps.Count) IPs"
        
        try {
            $ipGroup = Update-IpGroup -Token $Token `
                -SubscriptionId $subscriptionId `
                -ResourceGroup $resourceGroup `
                -IpAddresses $groupIps `
                -IpGroupName $groupName
                
            $ipGroupResults += @{
                id = $ipGroup.id
                name = $groupName
                count = $groupIps.Count
            }
            Write-FunctionLog "Updated/Created IP Group $groupName. ID: $($ipGroup.id)"
        }
        catch {
            $errorRecord = $_
            $errorMessage = $errorRecord.Exception.Message
            $stackTrace = $errorRecord.ScriptStackTrace
            
            Write-FunctionLog "Failed to update group $groupName. Error: $errorMessage" -Level "Error"
            Write-FunctionLog "Stack trace: $stackTrace" -Level "Error"
            
            throw "Failed to process IP group '$groupName': $errorMessage"
        }
    }

    Write-FunctionLog "Updating Rule Collection Group with $($ipGroupResults.Count) IP groups..."
    
    $result = Update-RuleCollectionGroup -Token $Token `
        -SubscriptionId $subscriptionId `
        -ResourceGroup $resourceGroup `
        -FirewallPolicyName $policyName `
        -IpGroupIds ($ipGroupResults.id)

    Write-SuccessResponse -Message "Firewall policy updated successfully" -Details @{
        ipGroupIds = $ipGroupResults.id
        ruleCollectionGroup = $result
        totalIpsProcessed = $blocklistIps.Count
        groupsCreated = $ipGroups.Count
        ipsPerGroup = $ipGroups | ForEach-Object { $_.Count }
        requestInfo = @{
            blocklistUrl = $blocklistUrl
            maxTotalIps = $maxTotalIps
            maxIpsPerGroup = $maxIpsPerGroup
            maxIpGroups = $maxIpGroups
        }
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
    $apiVersion = "2024-01-01"
    $ipGroupsUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Network/ipGroups?api-version=$apiVersion"
    
    try {
        Write-FunctionLog "Making API request to: $ipGroupsUrl"
        $ipGroups = Invoke-AzureRestMethod -Method Get -Uri $ipGroupsUrl `
            -Headers @{ "Authorization" = "Bearer $Token" } `
            -MaxRetries 3 `
            -RetryDelay 5
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

    # Track which groups were updated
    $updatedGroups = @()
    $unblocked = [System.Collections.ArrayList]@()

    # Process each IP group
    foreach ($group in $blockedIpGroups) {
        # Get current IPs both with and without CIDR
        $currentIpsWithCidr = $group.properties.ipAddresses
        $currentIpsWithoutCidr = $currentIpsWithCidr | ForEach-Object { $_ -replace '/32$', '' }
        
        # Check for matches in both formats
        $ipsToRemove = $validIps | Where-Object { 
            $ip = $_
            $ip -in $currentIpsWithoutCidr -or "$ip/32" -in $currentIpsWithCidr 
        }
        
        if ($ipsToRemove) {
            Write-FunctionLog "Found $($ipsToRemove.Count) IPs to remove from group $($group.name)"
            
            # Keep original CIDR format for remaining IPs
            $remainingIps = $currentIpsWithCidr | Where-Object { 
                ($_ -replace '/32$', '') -notin $ipsToRemove 
            }
            
            if ($remainingIps.Count -eq 0) {
                Write-FunctionLog "Group would be empty, adding placeholder IP" -Level "Warning"
                $remainingIps = @("0.0.0.0/32")  # Placeholder IP if group would be empty
            }
            
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
                Write-FunctionLog "Successfully updated group $($group.name) with $($remainingIps.Count) IPs"
            }
            catch {
                Write-FunctionLog "Failed to update group $($group.name): $_" -Level "Error"
                throw
            }
        }
    }

    if ($updatedGroups.Count -eq 0) {
        Write-FunctionLog "No IP Groups needed updating" -Level "Warning"
        Write-SuccessResponse -Message "No IPs found to unblock" -Details @{
            requestInfo = @{
                providedIps = $IpsToUnblock
                validIps = $validIps
            }
        }
        return
    }

    # Update Rule Collection Group with all groups
    Write-FunctionLog "Updating Rule Collection Group..."
    $result = Update-RuleCollectionGroup -Token $Token `
        -SubscriptionId $subscriptionId `
        -ResourceGroup $resourceGroup `
        -FirewallPolicyName $policyName `
        -IpGroupIds ($blockedIpGroups | ForEach-Object { $_.id })  # Get id from each group
    
    Write-SuccessResponse -Message "Successfully unblocked IPs" -Details @{
        updatedGroups = $updatedGroups
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
        
        $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $tokenBody
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
                # Pass parsed body to unblock action
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

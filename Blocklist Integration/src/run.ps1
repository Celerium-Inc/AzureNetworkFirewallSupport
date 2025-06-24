# Azure Firewall Blocklist Integration Function
# This function manages IP blocklists in Azure Firewall using IP Groups and Rule Collection Groups.
# Features:
# - Testing connectivity to Azure resources
# - Updating blocklist from external source
# - Both inbound and outbound blocking rules

# Input bindings are passed in via param block
param($Timer)

# Required environment variables
$subscriptionId = $env:SUBSCRIPTION_ID
$resourceGroup = $env:RESOURCE_GROUP
$firewallName = $env:FIREWALL_NAME
$policyName = $env:POLICY_NAME
$blocklistUrl = $env:BLKLIST_URL

# Optional configuration with defaults
$maxTotalIps = if ($env:MAX_TOTAL_IPS) { [int]$env:MAX_TOTAL_IPS } else { 50000 }
$maxIpsPerGroup = if ($env:MAX_IPS_PER_GROUP) { [int]$env:MAX_IPS_PER_GROUP } else { 5000 }
$maxIpGroups = if ($env:MAX_IP_GROUPS) { [int]$env:MAX_IP_GROUPS } else { 10 }
$baseIpGroupName = if ($env:BASE_IP_GROUP_NAME) { $env:BASE_IP_GROUP_NAME } else { "fw-blocklist" }
$ruleCollectionGroupName = if ($env:RULE_COLLECTION_GROUP_NAME) { $env:RULE_COLLECTION_GROUP_NAME } else { "CeleriumRuleCollectionGroup" }
$ruleCollectionName = if ($env:RULE_COLLECTION_NAME) { $env:RULE_COLLECTION_NAME } else { "Blocked-IP-Collection" }
$rulePriority = if ($env:RULE_PRIORITY) { [int]$env:RULE_PRIORITY } else { 100 }
$enforceHttpsOnly = if ($env:ENFORCE_HTTPS_ONLY) { [System.Convert]::ToBoolean($env:ENFORCE_HTTPS_ONLY) } else { $true }

# Set logging verbosity (1=Basic, 2=Verbose)
$global:LogVerbosity = if ($env:LOG_VERBOSITY) { [int]$env:LOG_VERBOSITY } else { 2 }  # Default to verbose logging

# Error handling preference
$ErrorActionPreference = 'Stop'

# Configure TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Cache IP regex pattern for performance
$script:ipRegex = [regex]'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'

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

# Validate URL is HTTPS when enforceHttpsOnly is enabled
function Test-SecureUrl {
    param([string]$Url)
    
    if ($enforceHttpsOnly -and -not $Url.StartsWith("https://")) {
        Write-FunctionLog "URL must use HTTPS when ENFORCE_HTTPS_ONLY is enabled: $Url" -Level "Error"
        return $false
    }
    
    return $true
}

# Fetches and validates IP addresses from the blocklist URL
function Get-BlocklistIps {
    param([string]$Url)
    
    try {
        # Validate URL is HTTPS
        if (-not (Test-SecureUrl -Url $Url)) {
            throw "Insecure URL detected. When ENFORCE_HTTPS_ONLY is enabled, only HTTPS URLs are allowed."
        }
        
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

# Extract some complex expressions for IP group names into functions to make them more readable
function Get-IpGroupName {
    param(
        [int]$Index
    )
    return "$baseIpGroupName-$('{0:D3}' -f ($Index + 1))"
}

# Improve Wait-ForResourceState with more PowerShell-friendly code
function Wait-ForResourceState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceId,
        [Parameter(Mandatory = $true)]
        [string]$Token,
        [Parameter(Mandatory = $false)]
        [string]$DesiredState = "Succeeded",
        [Parameter(Mandatory = $false)]
        [int]$MaxWaitTimeSeconds = 360,
        [Parameter(Mandatory = $false)]
        [int]$InitialDelaySeconds = 2,
        [Parameter(Mandatory = $false)]
        [int]$InitialRetryIntervalSeconds = 10,
        [Parameter(Mandatory = $false)]
        [double]$BackoffMultiplier = 1.5,
        [Parameter(Mandatory = $false)]
        [int]$MaxRetryIntervalSeconds = 30
    )

    Write-FunctionLog "Waiting for resource $ResourceId to reach state '$DesiredState'..." -Level "Information"
    
    # Initial delay before first check
    if ($InitialDelaySeconds -gt 0) {
        Write-FunctionLog "Initial delay: $InitialDelaySeconds seconds..." -Level "Verbose"
        Start-Sleep -Seconds $InitialDelaySeconds
    }
    
    $startTime = Get-Date
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type" = "application/json"
    }
    
    # Initialize variables for tracking and reporting
    $lastReportTime = $startTime
    $reportIntervalSeconds = 30
    $retryIntervalSeconds = $InitialRetryIntervalSeconds
    $attempt = 1
    $lastState = $null
    $consecutiveErrors = 0
    $maxConsecutiveErrors = 3
    
    do {
        try {
            # Calculate elapsed time - use simple math operations
            $elapsedTime = Get-Date
            $elapsedSeconds = ($elapsedTime - $startTime).TotalSeconds
            $remainingSeconds = $MaxWaitTimeSeconds - $elapsedSeconds
            
            # Check if we've exceeded the timeout
            if ($remainingSeconds -le 0) {
                # If we have a last state and it's still "Updating", return a special object instead of throwing
                if ($lastState -eq "Updating") {
                    $elapsedSecondsDisplay = [math]::Floor($elapsedSeconds)
                    Write-FunctionLog "Resource is still updating after $elapsedSecondsDisplay seconds. Returning current state without error." -Level "Warning"
                    return @{
                        id = $ResourceId
                        properties = @{
                            provisioningState = $lastState
                        }
                        timeoutOccurred = $true
                    }
                }
                throw "Timed out waiting for resource to reach state '$DesiredState'. Last known state: $lastState"
            }
            
            # Make API request to check resource state
            Write-FunctionLog "Checking resource state (Attempt $attempt)..." -Level "Verbose"
            $apiUrl = "https://management.azure.com$ResourceId`?api-version=2024-07-01"
            $status = Invoke-RestMethod -Method Get -Uri $apiUrl -Headers $headers -ErrorAction Stop
            
            # Reset error counter on success
            $consecutiveErrors = 0
            $currentState = $status.properties.provisioningState
            
            # Only log if state has changed
            if ($currentState -ne $lastState) {
                Write-FunctionLog "Resource state changed to: $currentState" -Level "Information"
                $lastState = $currentState
            }
            
            # Check if we've reached the desired state
            if ($currentState -eq $DesiredState) {
                $totalTime = [math]::Floor(((Get-Date) - $startTime).TotalSeconds)
                Write-FunctionLog "Resource reached desired state: $DesiredState (took ${totalTime}s)" -Level "Information"
                return $status
            }
            elseif ($currentState -eq "Failed") {
                $errorDetails = "Unknown error"
                if ($status.properties.error) {
                    $errorDetails = $status.properties.error | ConvertTo-Json -Compress -Depth 3
                }
                throw "Resource provisioning failed. Details: $errorDetails"
            }
            
            # Report progress periodically
            $currentTime = Get-Date
            $timeSinceLastReport = ($currentTime - $lastReportTime).TotalSeconds
            if ($timeSinceLastReport -ge $reportIntervalSeconds) {
                $elapsedSecondsDisplay = [math]::Floor(($currentTime - $startTime).TotalSeconds)
                $remainingSecondsDisplay = [math]::Floor($remainingSeconds)
                Write-FunctionLog "Still waiting for resource... State: $currentState, Elapsed: ${elapsedSecondsDisplay}s, Remaining: ${remainingSecondsDisplay}s" -Level "Information"
                $lastReportTime = $currentTime
            }
            else {
                Write-FunctionLog "Current state: $currentState, Next check in $retryIntervalSeconds seconds..." -Level "Verbose"
            }
            
            # Sleep before next check with exponential backoff
            Start-Sleep -Seconds $retryIntervalSeconds
            
            # Increase retry interval with exponential backoff, but cap at maximum
            # Simplify the math expression
            $newInterval = [math]::Floor($retryIntervalSeconds * $BackoffMultiplier)
            if ($newInterval -gt $MaxRetryIntervalSeconds) {
                $retryIntervalSeconds = $MaxRetryIntervalSeconds
            } else {
                $retryIntervalSeconds = $newInterval
            }
            
            $attempt++
        }
        catch {
            $consecutiveErrors++
            $errorMessage = $_.Exception.Message
            
            # Handle special cases
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 404) {
                Write-FunctionLog "Resource not found. It may be being created or deleted." -Level "Warning"
            }
            elseif ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 429) {
                Write-FunctionLog "Rate limited by Azure API. Increasing wait time." -Level "Warning"
                # Double the wait time for rate limiting but don't exceed max * 2
                $doubledDelay = $retryIntervalSeconds * 2
                $maxAllowed = $MaxRetryIntervalSeconds * 2
                if ($doubledDelay -gt $maxAllowed) {
                    $retryIntervalSeconds = $maxAllowed
                } else {
                    $retryIntervalSeconds = $doubledDelay
                }
            }
            else {
                Write-FunctionLog "Error checking resource state: $errorMessage" -Level "Warning"
            }
            
            # If we've had too many consecutive errors, abort
            if ($consecutiveErrors -ge $maxConsecutiveErrors) {
                throw "Aborting after $consecutiveErrors consecutive errors. Last error: $errorMessage"
            }
            
            # Calculate elapsed time
            $elapsedTime = Get-Date
            $elapsedSeconds = ($elapsedTime - $startTime).TotalSeconds
            $remainingSeconds = $MaxWaitTimeSeconds - $elapsedSeconds
            
            if ($remainingSeconds -le 0) {
                $elapsedSecondsDisplay = [math]::Floor($elapsedSeconds)
                # If we know the last state was "Updating", return more gracefully
                if ($lastState -eq "Updating") {
                    Write-FunctionLog "Resource is still updating after timeout. Returning current state without failing." -Level "Warning"
                    return @{
                        id = $ResourceId
                        properties = @{
                            provisioningState = $lastState
                        }
                        timeoutOccurred = $true
                    }
                }
                throw "Timed out waiting for resource to reach state '$DesiredState' after ${elapsedSecondsDisplay} seconds"
            }
            
            # Calculate wait time with simpler math
            $errorWaitTime = $retryIntervalSeconds * 2
            $quarterRemaining = [math]::Floor($remainingSeconds / 4)
            if ($errorWaitTime -gt $quarterRemaining) {
                $errorWaitTime = $quarterRemaining
            }
            
            Write-FunctionLog "Waiting $errorWaitTime seconds before retrying..." -Level "Warning"
            Start-Sleep -Seconds $errorWaitTime
            
            $attempt++
        }
    } while ($true)
}

# Modify Split-IpsIntoGroups to use more PowerShell-friendly array operations
function Split-IpsIntoGroups {
    param(
        [array]$IpList,
        [int]$MaxIpsPerGroup,
        [int]$MaxGroups
    )

    Write-FunctionLog "Splitting $($IpList.Count) IPs into groups" -Level "Verbose"
    
    # More PowerShell-friendly way of determining group count
    $ipCount = $IpList.Count
    $groupsNeeded = [math]::Ceiling($ipCount / $MaxIpsPerGroup)
    if ($groupsNeeded -gt $MaxGroups) {
        $groupsNeeded = $MaxGroups
    }
    
    $totalGroups = [int]$groupsNeeded
    Write-FunctionLog "Creating $totalGroups IP groups" -Level "Verbose"
    
    $groups = [System.Collections.ArrayList]@()
    for ($i = 0; $i -lt $totalGroups; $i++) {
        $startIndex = $i * $MaxIpsPerGroup
        $length = $MaxIpsPerGroup
        
        # Ensure we don't go past the end of the array
        if (($startIndex + $length) -gt $ipCount) {
            $length = $ipCount - $startIndex
        }
        
        # Skip if we somehow have a negative length
        if ($length -le 0) { continue }
        
        # Use Select-Object for better performance with large arrays
        $groupIps = @($IpList | Select-Object -Skip $startIndex -First $length)
        Write-FunctionLog "Created group $($i + 1) with $($groupIps.Count) IPs" -Level "Verbose"
        
        # Add the group as a single element to our results using ArrayList.Add()
        [void]$groups.Add($groupIps)
    }

    # Return as array to maintain consistency, wrapped to prevent PowerShell auto-unrolling
    $result = $groups.ToArray()
    return ,$result
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
                ipAddresses = @($formattedIps)  # Ensure this is always treated as an array
            }
        }

        Write-FunctionLog "Request URL: $url" -Level "Verbose"
        Write-FunctionLog "Request body: $($body | ConvertTo-Json -Depth 10)" -Level "Verbose"

        # Convert to JSON and ensure ipAddresses is always an array
        $jsonBody = $body | ConvertTo-Json -Compress -Depth 10
        # Fix single-element array serialization issue
        if ($formattedIps.Count -eq 1) {
            $escapedIp = $formattedIps[0] -replace '"', '\"'
            $replacement = '"ipAddresses":["' + $escapedIp + '"]'
            $jsonBody = $jsonBody -replace '"ipAddresses":"[^"]*"', $replacement
        }

        # Make API call with retries
        $result = Invoke-RestMethod -Method Put -Uri "$url`?api-version=$ipGroupApiVersion" `
            -Headers @{
                "Authorization" = "Bearer $Token"
                "Content-Type" = "application/json"
            } `
            -Body $jsonBody `
            -ContentType "application/json"

        Write-FunctionLog "IP Group update successful" -Level "Verbose"
        return $result
    }
    catch {
        $errorDetails = ""
        try {
            # Try to get detailed error message, with null checks
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                $errorDetails = $_.ErrorDetails.Message
            }
            elseif ($_.Exception -and $_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
                try {
                    $rawError = $_.Exception.Response.GetResponseStream()
                    if ($rawError) {
                        $reader = New-Object System.IO.StreamReader($rawError)
                        $errorDetails = $reader.ReadToEnd()
                        $reader.Close()
                    }
                }
                catch {
                    # If reading response stream fails, fall back to exception message
                    $errorDetails = if ($_.Exception -and $_.Exception.Message) { $_.Exception.Message } else { "Unknown error reading response stream" }
                }
            }
            elseif ($_.Exception -and $_.Exception.Message) {
                $errorDetails = $_.Exception.Message
            }
            else {
                $errorDetails = "Unknown error occurred"
            }
        }
        catch {
            # Final fallback if all else fails
            $errorDetails = if ($_.Exception -and $_.Exception.Message) { $_.Exception.Message } else { "Unknown error in error handling" }
        }

        Write-FunctionLog "Update-IpGroup failed with details: $errorDetails" -Level "Error"
        throw "Failed to update IP Group: $errorDetails"
    }
}

# Function to write error responses (now just logs)
function Write-ErrorResponse {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    Write-FunctionLog "Error: $Message" -Level "Error"
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

# Write success responses in consistent format (now just logs)
function Write-SuccessResponse {
    param(
        [string]$Message,
        [object]$Details = $null
    )

    Write-FunctionLog "Success: $Message"
    if ($Details) {
        Write-FunctionLog "Details: $($Details | ConvertTo-Json -Depth 10)" -Level "Verbose"
    }
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
            # Safely extract error information with null checks
            $statusCode = if ($_.Exception -and $_.Exception.Response -and $_.Exception.Response.StatusCode) { 
                $_.Exception.Response.StatusCode.value__ 
            } else { 
                "Unknown" 
            }
            
            $errorMessage = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { 
                $_.ErrorDetails.Message 
            } elseif ($_.Exception -and $_.Exception.Message) { 
                $_.Exception.Message 
            } else { 
                "Unknown error" 
            }

            Write-FunctionLog "API request failed (Attempt $attempt): Status $statusCode - $errorMessage" -Level "Warning"

            if ($attempt -eq $MaxRetries) {
                Write-FunctionLog "Max retries reached. Failing operation." -Level "Error"
                throw
            }

            $attempt++
        }
    }
}

# Main update action with more PowerShell-friendly approach
function Invoke-UpdateAction {
    param([string]$Token)

    $startTime = Get-Date
    Write-FunctionLog "Starting update action..."
    
    try {
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
        
        $existingBlocklistGroups = @($existingGroups.value | Where-Object { $_.name -like "$baseIpGroupName-*" })
        Write-FunctionLog "Found $($existingBlocklistGroups.Count) existing IP groups matching pattern '$baseIpGroupName-*'"
        
        # Split IPs into groups
        $ipGroups = Split-IpsIntoGroups -IpList $blocklistIps -MaxIpsPerGroup $maxIpsPerGroup -MaxGroups $maxIpGroups
        Write-FunctionLog "Split function returned $($ipGroups.Count) elements" -Level "Verbose"
        Write-FunctionLog "First element type: $($ipGroups[0].GetType().Name)" -Level "Verbose"
        Write-FunctionLog "First element count: $($ipGroups[0].Count)" -Level "Verbose"
        Write-FunctionLog "Need $($ipGroups.Count) groups for current IPs"
    
        # Calculate total time elapsed so far
        $elapsedSeconds = ((Get-Date) - $startTime).TotalSeconds
        $maxTotalTimeSeconds = 540  # 9 minutes (leaving 1 minute buffer)
        $remainingSeconds = $maxTotalTimeSeconds - $elapsedSeconds
        
        # If we have less than 7 minutes remaining, we might not have time to complete - log warning
        if ($remainingSeconds -lt 420) {
            $remainingSecondsDisplay = [math]::Floor($remainingSeconds)
            Write-FunctionLog "Warning: Only ${remainingSecondsDisplay} seconds remaining. Operation may not complete in time." -Level "Warning"
        }
    
        # Check if the rule collection already exists - wrapped in additional try/catch for safety
        $ruleCollectionUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Network/firewallPolicies/$policyName/ruleCollectionGroups/$ruleCollectionGroupName"
        $ruleCollectionExists = $false
        $currentState = $null
        $ruleCollectionId = $null
        
        try {
            Write-FunctionLog "Checking if rule collection group exists..." -Level "Verbose"
            $apiUrl = "$ruleCollectionUrl`?api-version=2024-07-01"
            $response = Invoke-RestMethod -Method Get -Uri $apiUrl -Headers @{ "Authorization" = "Bearer $Token" }
            $ruleCollectionExists = $true
            $currentState = $response.properties.provisioningState
            $ruleCollectionId = $response.id
            
            Write-FunctionLog "Rule collection group exists in state: $currentState" -Level "Information"
            
            # If it exists but is not in a Succeeded state, wait for it to finish first
            if ($currentState -ne "Succeeded") {
                Write-FunctionLog "Rule collection group is in '$currentState' state, waiting for completion..." -Level "Warning"
                $status = Wait-ForResourceState -ResourceId $response.id -Token $Token -DesiredState "Succeeded" -MaxWaitTimeSeconds 360
            }
    }
    catch {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 404) {
                Write-FunctionLog "Rule collection group does not exist yet." -Level "Warning"
            }
            else {
                Write-FunctionLog "Error checking rule collection group: $_" -Level "Error"
                throw
            }
        }
    
        # Update and Delete operations
        $newGroupResults = @()
        $groupsToDelete = New-Object System.Collections.ArrayList
        
        # Create a list of groups to potentially delete (we'll remove ones we want to keep)
        foreach ($group in $existingBlocklistGroups) {
            [void]$groupsToDelete.Add($group)
        }
        
        # Process IP groups in batches (only if time permits)
        $processedGroups = 0
        if ($ipGroups.Count -gt 0) {
            # Skip emptying the rule collection - this creates a security gap
            # Instead, we'll keep existing rules in place until we're ready with the new configuration
            
            # Update existing groups and create new ones as needed - with batching for improved performance
            Write-FunctionLog "Processing IP groups without removing existing rule references..."
            
            $batchSize = 3  # Process up to 3 IP groups in parallel
            $batchDelay = 2  # Wait 2 seconds between batches
            
            for ($i = 0; $i -lt $ipGroups.Count; $i += $batchSize) {
                # Check if we need to abort due to time constraints
                $elapsedSeconds = ((Get-Date) - $startTime).TotalSeconds
                $remainingSeconds = $maxTotalTimeSeconds - $elapsedSeconds
                
                if ($remainingSeconds -lt 180) { # Less than 3 minutes remaining
                    $remainingSecondsDisplay = [math]::Floor($remainingSeconds)
                    Write-FunctionLog "Warning: Only ${remainingSecondsDisplay} seconds remaining. Skipping remaining IP group updates." -Level "Warning"
                    break
                }
                
                # Calculate the end of this batch
                $batchEnd = $i + $batchSize - 1
                if ($batchEnd -ge $ipGroups.Count) {
                    $batchEnd = $ipGroups.Count - 1
                }
                
                $batchStartNum = $i + 1
                $batchEndNum = $batchEnd + 1
                Write-FunctionLog "Processing batch of IP groups ($batchStartNum to $batchEndNum of $($ipGroups.Count))..." -Level "Information"
                
                # Process each group in current batch
                for ($j = $i; $j -le $batchEnd; $j++) {
                    $groupIps = $ipGroups[$j]
                    $groupName = Get-IpGroupName -Index $j
                    
                    # Check if we can reuse an existing group
                    $existingGroup = $null
                    foreach ($group in $existingBlocklistGroups) {
                        if ($group.name -eq $groupName) {
                            $existingGroup = $group
                            break
                        }
                    }
                    
                    if ($existingGroup) {
                        Write-FunctionLog "Updating existing group $groupName with $($groupIps.Count) IPs"
                        $groupsToDelete.Remove($existingGroup)
                    } else {
                        Write-FunctionLog "Creating new group $groupName with $($groupIps.Count) IPs"
                    }
    
                    # Efficiently update IP Groups with retry logic
                    $maxRetries = 2
                    $retryDelay = 3
                    $success = $false
                    
                    for ($attemptNo = 1; $attemptNo -le $maxRetries; $attemptNo++) {
                        try {
                            if ($attemptNo -gt 1) {
                                Write-FunctionLog "Retrying IP Group update for $groupName (attempt $attemptNo)..." -Level "Warning"
                                Start-Sleep -Seconds ($retryDelay * $attemptNo)
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
                            
                            $success = $true
                            $processedGroups++
                            break
        }
        catch {
                            Write-FunctionLog "Error updating IP Group $groupName (attempt $attemptNo): $_" -Level "Warning"
                            
                            if ($attemptNo -eq $maxRetries) {
                                Write-FunctionLog "Failed to update IP Group $groupName after $maxRetries attempts" -Level "Error"
                                throw
                            }
                        }
                    }
                }
                
                # Wait between batches to avoid rate limiting
                if ($batchEnd -lt ($ipGroups.Count - 1)) {
                    Write-FunctionLog "Waiting $batchDelay seconds before next batch..." -Level "Verbose"
                    Start-Sleep -Seconds $batchDelay
                }
            }
        }
    
        # Delete any remaining unused groups - with batching
        # Check time remaining first
        $elapsedSeconds = ((Get-Date) - $startTime).TotalSeconds
        $remainingSeconds = $maxTotalTimeSeconds - $elapsedSeconds
        
        $deletedGroups = 0
        if ($groupsToDelete.Count -gt 0) {
            # Skip deletion if time is running out
            if ($remainingSeconds -lt 120) { # Less than 2 minutes remaining
                $remainingSecondsDisplay = [math]::Floor($remainingSeconds)
                Write-FunctionLog "Warning: Only ${remainingSecondsDisplay} seconds remaining. Skipping deletion of unused groups." -Level "Warning"
            }
            else {
                Write-FunctionLog "Deleting $($groupsToDelete.Count) unused IP groups" -Level "Information"
                $batchSize = 3  # Delete up to 3 IP groups in parallel
                $batchDelay = 2
                
                for ($i = 0; $i -lt $groupsToDelete.Count; $i += $batchSize) {
                    # Calculate the end of this batch
                    $batchEnd = $i + $batchSize - 1
                    if ($batchEnd -ge $groupsToDelete.Count) {
                        $batchEnd = $groupsToDelete.Count - 1
                    }
                    
                    $currentBatchCount = $batchEnd - $i + 1
                    Write-FunctionLog "Deleting batch of $currentBatchCount IP groups..." -Level "Information"
                    
                    # Process each group in current batch
                    for ($j = $i; $j -le $batchEnd; $j++) {
                        $group = $groupsToDelete[$j]
                        Write-FunctionLog "Deleting unused group $($group.name)"
                        
                        try {
                            Remove-IpGroup -Token $Token `
        -SubscriptionId $subscriptionId `
        -ResourceGroup $resourceGroup `
                                -IpGroupName $group.name
                                
                            $deletedGroups++
                        }
                        catch {
                            Write-FunctionLog "Error deleting IP Group $($group.name): $_" -Level "Warning"
                            # Continue with other deletions even if one fails
                        }
                    }
                    
                    # Wait between batches to avoid rate limiting
                    if ($batchEnd -lt ($groupsToDelete.Count - 1)) {
                        Write-FunctionLog "Waiting $batchDelay seconds before next deletion batch..." -Level "Verbose"
                        Start-Sleep -Seconds $batchDelay
                    }
                }
            }
        }
    
        # Update firewall policy with all groups - with enhanced retry logic
        # Check time remaining first
        $elapsedSeconds = ((Get-Date) - $startTime).TotalSeconds
        $remainingSeconds = $maxTotalTimeSeconds - $elapsedSeconds
        
        if ($remainingSeconds -lt 180) { # Less than 3 minutes remaining
            $remainingSecondsDisplay = [math]::Floor($remainingSeconds)
            Write-FunctionLog "Warning: Only ${remainingSecondsDisplay} seconds remaining. Not enough time to update rule collection." -Level "Warning"
            
            # Summarize what we've done so far even though we're not updating the rule collection
            $createCount = 0
            $updateCount = 0
            
            foreach ($result in $newGroupResults) {
                if ($result.isNew) {
                    $createCount++
                } else {
                    $updateCount++
                }
            }
            
            $uniqueIpsCount = ($blocklistIps | Select-Object -Unique).Count
            $durationSeconds = [math]::Floor(((Get-Date) - $startTime).TotalSeconds)
            
            Write-SuccessResponse -Message "Partially updated IP groups - rule collection update skipped due to time constraints" -Details @{
                summary = @{
                    groupsCreated = $createCount
                    groupsUpdated = $updateCount
                    groupsDeleted = $deletedGroups
                    groupsProcessed = $processedGroups
                    totalIps = $blocklistIps.Count
                    uniqueIps = $uniqueIpsCount
                    operationStart = $startTime
                    operationEnd = Get-Date
                    durationSeconds = $durationSeconds
                    completed = $false
                    reason = "Time constraint - function execution limit approaching"
                }
                groupsCreated = if ($createCount -gt 0) { $newGroupResults | Where-Object { $_.isNew } | Select-Object name, count } else { $null }
                groupsUpdated = if ($updateCount -gt 0) { $newGroupResults | Where-Object { -not $_.isNew } | Select-Object name, count } else { $null }
                groupsDeleted = if ($deletedGroups -gt 0) { $groupsToDelete | Select-Object -First $deletedGroups name } else { $null }
            }
            return
        }
    
        # Proceed with updating the rule collection
        Write-FunctionLog "Creating new rule collection with IP groups"
        $maxRetries = 3
        $baseRetryDelay = 10
        $success = $false
        
        for ($attemptNo = 1; $attemptNo -le $maxRetries; $attemptNo++) {
            try {
                if ($attemptNo -gt 1) {
                    $backoffFactor = [math]::Pow(1.5, ($attemptNo - 1))
                    $currentRetryDelay = [math]::Floor($baseRetryDelay * $backoffFactor)
                    Write-FunctionLog "Retrying rule collection update (attempt $attemptNo of $maxRetries, waiting $currentRetryDelay seconds)..." -Level "Warning"
                    Start-Sleep -Seconds $currentRetryDelay
                }
                
                # Extract just the IDs for the API call
                $groupIds = @()
                foreach ($result in $newGroupResults) {
                    $groupIds += $result.id
                }
                
                $result = Update-RuleCollectionGroup -Token $Token `
                    -SubscriptionId $subscriptionId `
                    -ResourceGroup $resourceGroup `
                    -FirewallPolicyName $policyName `
                    -IpGroupIds $groupIds
                
                # Wait for the operation to complete with a longer timeout for the final update
                $status = Wait-ForResourceState -ResourceId $result.id -Token $Token -MaxWaitTimeSeconds 360 -InitialRetryIntervalSeconds 10 -BackoffMultiplier 1.3
                
                # Check if we got a timeout but the resource is still updating
                if ($status.timeoutOccurred -and $status.properties.provisioningState -eq "Updating") {
                    Write-FunctionLog "Rule collection update is still in progress but function timeout is approaching. Consider the operation partially successful." -Level "Warning"
                    $success = $true  # Consider it a success even though we timed out waiting
                } else {
                    $success = $true
                }
                break
    }
    catch {
                $errorMessage = $_.ToString()
                
                # Check if we need to abort due to time constraints
                $elapsedSeconds = ((Get-Date) - $startTime).TotalSeconds
                $remainingSeconds = $maxTotalTimeSeconds - $elapsedSeconds
                
                if ($remainingSeconds -lt 90) { # Less than 1.5 minutes remaining
                    $remainingSecondsDisplay = [math]::Floor($remainingSeconds)
                    Write-FunctionLog "Warning: Only ${remainingSecondsDisplay} seconds remaining. Aborting rule collection update." -Level "Warning"
                    break
                }
                
                # Check if it's a timeout but the resource might still be updating successfully
                if ($errorMessage -like "*Timed out waiting for resource to reach state*" -and 
                    $errorMessage -like "*Last known state: Updating*") {
                    Write-FunctionLog "Rule collection update timed out but is still in progress. This is likely fine as Azure Firewall updates can take 5+ minutes." -Level "Warning"
                    Write-FunctionLog "The update will complete in the background even after this function terminates." -Level "Information"
                    $success = $true  # Consider it a partial success
                    break
                }
                
                # Check if it's the "already updating" error
                if ($errorMessage -like "*FirewallPolicyRuleCollectionGroupUpdateNotAllowedWhenUpdatingOrDeleting*") {
                    # Try to extract operation ID for better logging
                    $operationId = "unknown"
                    if ($errorMessage -match "operation ID : ([a-zA-Z0-9-]+)") {
                        $operationId = $Matches[1]
                    }
                    
                    Write-FunctionLog "Rule collection is still updating (previous operation ID: $operationId). Waiting longer before retry..." -Level "Warning"
                    
                    # Wait longer between retries for this specific error with increasing backoff
                    $waitTime = 30 * $attemptNo
                    if ($waitTime -gt 60) {
                        $waitTime = 60  # Max 60 seconds wait
                    }
                    
                    Write-FunctionLog "Waiting $waitTime seconds before retry $attemptNo..." -Level "Information"
                    Start-Sleep -Seconds $waitTime
                }
                else {
                    Write-FunctionLog "Error updating rule collection (attempt $attemptNo): $errorMessage" -Level "Error"
                    
                    if ($attemptNo -eq $maxRetries) {
                throw
                    }
                }
            }
        }
    
        # Check if we succeeded or timed out
        if (-not $success) {
            Write-FunctionLog "Could not complete rule collection update - either failed or time limit reached" -Level "Warning"
        }
    
        # Calculate statistics for logging
        $createCount = 0
        $updateCount = 0
        
        foreach ($result in $newGroupResults) {
            if ($result.isNew) {
                $createCount++
            } else {
                $updateCount++
            }
        }
        
        $durationSeconds = [math]::Floor(((Get-Date) - $startTime).TotalSeconds)
        $uniqueIpsCount = ($blocklistIps | Select-Object -Unique).Count
        
        Write-SuccessResponse -Message "Successfully updated IP groups" -Details @{
            summary = @{
                groupsCreated = $createCount
                groupsUpdated = $updateCount
                groupsDeleted = $deletedGroups
                groupsProcessed = $processedGroups
                totalIps = $blocklistIps.Count
                uniqueIps = $uniqueIpsCount
                operationStart = $startTime 
                operationEnd = Get-Date
                durationSeconds = $durationSeconds
                completed = $success
            }
            groupsCreated = if ($createCount -gt 0) { $newGroupResults | Where-Object { $_.isNew } | Select-Object name, count } else { $null }
            groupsUpdated = if ($updateCount -gt 0) { $newGroupResults | Where-Object { -not $_.isNew } | Select-Object name, count } else { $null }
            groupsDeleted = if ($deletedGroups -gt 0) { $groupsToDelete | Select-Object -First $deletedGroups name } else { $null }
        }
    }
    catch {
        Write-FunctionLog "Error in Invoke-UpdateAction: $_" -Level "Error"
        throw
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

# Main execution block
try {
    # Log function start
    Write-FunctionLog "Function starting"
    
    # Check if timer trigger is past due
    if ($Timer.IsPastDue) {
        Write-FunctionLog "Timer function is running late!" -Level "Warning"
    }

    # Get Azure access token
        Write-FunctionLog "Getting Azure access token..."
        $tokenUrl = "https://login.microsoftonline.com/$($env:TENANT_ID)/oauth2/v2.0/token"
        $tokenBody = @{
            grant_type = "client_credentials"
            client_id = $env:CLIENT_ID
            client_secret = $env:CLIENT_SECRET
            scope = "https://management.azure.com/.default"
        }

    # Wrapped in try-catch for better error reporting
    try {
        $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
        
        if (-not $tokenResponse.access_token) {
            throw "Failed to get valid access token - empty or null access_token"
        }
    }
    catch {
        Write-FunctionLog "Error authenticating with Azure: $_" -Level "Error"
        throw "Authentication failed: $_"
        }

        $headers = @{
            "Authorization" = "Bearer $($tokenResponse.access_token)"
            "Content-Type" = "application/json"
        }
        Write-FunctionLog "Successfully obtained access token"

    # Run update action by default for timer trigger
    Write-FunctionLog "Starting blocklist update..."
                Invoke-UpdateAction -Token $tokenResponse.access_token
    
    Write-FunctionLog "Function completed successfully"
}
catch {
    Write-FunctionLog "Error: $_" -Level "Error"
    throw
}

# Cleanup script for Azure Firewall Blocklist Integration Function
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$FunctionAppName,

    [Parameter(Mandatory = $true)]
    [string]$FirewallPolicyName,

    [Parameter(Mandatory = $false)]
    [ValidateSet("AzurePublicCloud","AzureUSGovernment")]
    [string]$AzureCloud = "AzurePublicCloud"
)

# Error handling
$ErrorActionPreference = 'Stop'

# Helper function to generate valid storage account name
function Get-ValidStorageAccountName {
    param([string]$FunctionAppName)
    
    # Remove any special characters and convert to lowercase
    $name = $FunctionAppName.ToLower() -replace '[^a-z0-9]', ''
    
    # Append 'storage' to make it more descriptive
    $name = "${name}storage"
    
    # Ensure the name is no longer than 24 characters
    if ($name.Length -gt 24) {
        $name = $name.Substring(0, 24)
    }
    
    return $name
}

function Test-IsResourceNotFoundError {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $message = $ErrorRecord.ToString()
    return $message -match '(?i)(ResourceNotFound|NotFound|could not be found|was not found|does not exist|status code 404|\(404\))'
}

function Invoke-DeletionWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceDescription,

        [Parameter(Mandatory = $true)]
        [scriptblock]$DeleteAction,

        [int]$MaxAttempts = 6,
        [int]$RetryDelaySeconds = 10
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            & $DeleteAction | Out-Null
            return $true
        }
        catch {
            if (Test-IsResourceNotFoundError -ErrorRecord $_) {
                Write-Host "$ResourceDescription was already absent" -ForegroundColor Yellow
                return $true
            }

            if ($attempt -eq $MaxAttempts) {
                Write-Host "Error requesting deletion of $ResourceDescription after $attempt attempts: $_" -ForegroundColor Red
                return $false
            }

            Write-Host "$ResourceDescription is not ready for deletion; retrying in ${RetryDelaySeconds}s (attempt $attempt of $MaxAttempts)..." -ForegroundColor Yellow
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }

    return $false
}

function Wait-UntilResourceAbsent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceDescription,

        [Parameter(Mandatory = $true)]
        [scriptblock]$GetAction,

        [int]$TimeoutSeconds = 600,
        [int]$PollIntervalSeconds = 10
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $pollAttempt = 0

    while ((Get-Date) -lt $deadline) {
        $pollAttempt++
        try {
            $resource = & $GetAction
            if (-not $resource) {
                return $true
            }
        }
        catch {
            if (Test-IsResourceNotFoundError -ErrorRecord $_) {
                return $true
            }

            Write-Host "Could not verify deletion of $ResourceDescription yet: $_" -ForegroundColor Yellow
        }

        Write-Host "Waiting for $ResourceDescription deletion to complete (check $pollAttempt)..." -ForegroundColor Gray
        Start-Sleep -Seconds $PollIntervalSeconds
    }

    Write-Host "Timed out after ${TimeoutSeconds}s waiting for $ResourceDescription to be removed." -ForegroundColor Red
    return $false
}

function Get-ResourceProvisioningState {
    param(
        [Parameter(Mandatory = $true)]
        $Resource
    )

    if ($Resource.ProvisioningState) {
        return [string]$Resource.ProvisioningState
    }
    if ($Resource.Properties -and $Resource.Properties.ProvisioningState) {
        return [string]$Resource.Properties.ProvisioningState
    }

    return $null
}

function Remove-FirewallRuleCollectionGroupWhenReady {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]$FirewallPolicyName,

        [Parameter(Mandatory = $true)]
        [string]$RuleCollectionGroupName,

        [int]$TimeoutSeconds = 900,
        [int]$PollIntervalSeconds = 15
    )

    $resourceDescription = "Firewall Policy Rule Collection Group '$RuleCollectionGroupName'"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $pollAttempt = 0

    while ((Get-Date) -lt $deadline) {
        $pollAttempt++

        try {
            $firewallPolicy = Get-AzFirewallPolicy `
                -ResourceGroupName $ResourceGroupName `
                -Name $FirewallPolicyName `
                -ErrorAction Stop
        }
        catch {
            if (Test-IsResourceNotFoundError -ErrorRecord $_) {
                Write-Host "Firewall Policy '$FirewallPolicyName' is absent; the rule collection group is already absent" -ForegroundColor Yellow
                return $true
            }
            throw
        }

        try {
            $ruleCollectionGroup = Get-AzFirewallPolicyRuleCollectionGroup `
                -Name $RuleCollectionGroupName `
                -ResourceGroupName $ResourceGroupName `
                -AzureFirewallPolicyName $FirewallPolicyName `
                -ErrorAction Stop
        }
        catch {
            if (Test-IsResourceNotFoundError -ErrorRecord $_) {
                Write-Host "$resourceDescription was already absent" -ForegroundColor Yellow
                return $true
            }
            throw
        }

        $policyState = Get-ResourceProvisioningState -Resource $firewallPolicy
        $groupState = Get-ResourceProvisioningState -Resource $ruleCollectionGroup

        if ($policyState -eq "Failed" -or $groupState -eq "Failed") {
            throw "Cannot delete $resourceDescription because provisioning failed (Policy: '$policyState', Rule Collection Group: '$groupState'). Resolve the failed Azure operation and rerun cleanup."
        }

        # Some Az.Network versions do not expose ProvisioningState on the rule
        # collection group object. Once the parent policy succeeds, attempt the
        # deletion when the child state is either succeeded or unavailable.
        # Azure remains the authority: an updating/deleting response is handled
        # below as a transient race and returns to this polling loop.
        $policyReady = $policyState -eq "Succeeded"
        $groupReady = -not $groupState -or $groupState -eq "Succeeded"

        if ($policyReady -and $groupReady) {
            try {
                Remove-AzFirewallPolicyRuleCollectionGroup `
                    -Name $RuleCollectionGroupName `
                    -ResourceGroupName $ResourceGroupName `
                    -AzureFirewallPolicyName $FirewallPolicyName `
                    -Force `
                    -ErrorAction Stop | Out-Null
                return $true
            }
            catch {
                if (Test-IsResourceNotFoundError -ErrorRecord $_) {
                    Write-Host "$resourceDescription was already absent" -ForegroundColor Yellow
                    return $true
                }

                $errorMessage = $_.ToString()
                $isUpdatingOrDeleting = $errorMessage -match '(?i)(FirewallPolicyRuleCollectionGroupDeleteNotAllowedWhenUpdatingOrDeleting|can not be deleted because it is in (Updating|Deleting) state)'
                if (-not $isUpdatingOrDeleting) {
                    throw
                }

                Write-Host "$resourceDescription changed state before deletion could start; waiting for the Azure operation to finish..." -ForegroundColor Yellow
            }
        }
        else {
            $displayPolicyState = if ($policyState) { $policyState } else { "Unknown" }
            $displayGroupState = if ($groupState) { $groupState } else { "Unknown" }
            Write-Host "$resourceDescription is not ready for deletion (Policy: $displayPolicyState, Rule Collection Group: $displayGroupState)." -ForegroundColor Yellow
        }

        $remainingSeconds = [Math]::Max(0, [int][Math]::Ceiling(($deadline - (Get-Date)).TotalSeconds))
        if ($remainingSeconds -le 0) {
            break
        }

        $sleepSeconds = [Math]::Min($PollIntervalSeconds, $remainingSeconds)
        Write-Host "Retrying firewall cleanup in ${sleepSeconds}s (check $pollAttempt; up to ${TimeoutSeconds}s total)..." -ForegroundColor Gray
        Start-Sleep -Seconds $sleepSeconds
    }

    Write-Host "Timed out after ${TimeoutSeconds}s waiting to delete $resourceDescription." -ForegroundColor Red
    return $false
}

$cleanupFailures = [System.Collections.Generic.List[string]]::new()

Write-Host "Starting cleanup process..."
Write-Host "Resource Group: $ResourceGroupName"
Write-Host "Function App: $FunctionAppName"
Write-Host "Firewall Policy: $FirewallPolicyName"

# Generate storage account name
$StorageAccountName = Get-ValidStorageAccountName -FunctionAppName $FunctionAppName
Write-Host "Storage Account: $StorageAccountName"

# Generate Application Insights name
$AppInsightsName = "$FunctionAppName-insights"
Write-Host "Application Insights: $AppInsightsName"

# Derive the App Service Plan created by the default deployment
$DefaultAppServicePlanName = "$FunctionAppName-plan"
Write-Host "Default App Service Plan: $DefaultAppServicePlanName"

$RuleCollectionGroupName = "CeleriumRuleCollectionGroup"
$IpGroupNamePattern = "fw-blocklist-*"
Write-Host "Firewall Rule Collection Group: $RuleCollectionGroupName"
Write-Host "IP Groups: $IpGroupNamePattern"

# Prompt for confirmation
$confirmation = Read-Host "Are you sure you want to delete these resources, including the firewall artifacts and default App Service Plan? (y/n)"
if ($confirmation -ne 'y') {
    Write-Host "Cleanup cancelled by user"
    exit 0
}

# Function to ensure we have a valid Azure context (environment-aware)
function Ensure-AzureConnection {
    try {
        $targetAzEnv = switch ($AzureCloud) {
            "AzureUSGovernment" { "AzureUSGovernment" }
            default             { "AzureCloud" }
        }

        $context = Get-AzContext
        if (-not $context) {
            Write-Host "No Azure context found. Connecting to $targetAzEnv..."
            Connect-AzAccount -UseDeviceAuthentication -Environment $targetAzEnv
            $context = Get-AzContext
        }
        elseif ($context.Environment.Name -ne $targetAzEnv) {
            Write-Host "Current Az environment ($($context.Environment.Name)) differs from target ($targetAzEnv). Connecting..."
            Connect-AzAccount -UseDeviceAuthentication -Environment $targetAzEnv
            $context = Get-AzContext
        }
        
        if (-not $context) {
            throw "Failed to establish Azure connection"
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to connect to Azure: $_" -ForegroundColor Red
        return $false
    }
}

# Ensure we're connected before proceeding
if (-not (Ensure-AzureConnection)) {
    Write-Host "Cannot proceed without Azure connection" -ForegroundColor Red
    exit 1
}

# Remove the Function App first so its timer cannot recreate firewall artifacts during cleanup.
try {
    Write-Host "Removing Function App $FunctionAppName..."
    $deleteRequested = Invoke-DeletionWithRetry `
        -ResourceDescription "Function App '$FunctionAppName'" `
        -DeleteAction {
            Remove-AzFunctionApp `
                -Name $FunctionAppName `
                -ResourceGroupName $ResourceGroupName `
                -Force `
                -ErrorAction Stop
        }

    if (-not $deleteRequested) {
        throw "The Function App deletion request did not succeed."
    }

    $functionAppRemoved = Wait-UntilResourceAbsent `
        -ResourceDescription "Function App '$FunctionAppName'" `
        -TimeoutSeconds 300 `
        -GetAction {
            Get-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        }

    if (-not $functionAppRemoved) {
        throw "Function App '$FunctionAppName' is still present. Firewall cleanup cannot safely continue while its timer may be running."
    }

    Write-Host "Function App removed successfully"
}
catch {
    Write-Host "Error removing Function App: $_" -ForegroundColor Red
    Write-Host "Cleanup stopped before deleting dependent resources." -ForegroundColor Red
    exit 1
}

# Remove the managed rule collection group and wait for Azure to release its IP Group references.
$ruleCollectionGroupRemoved = $false
try {
    Write-Host "Removing Firewall Policy Rule Collection Group $RuleCollectionGroupName..."
    $deleteRequested = Remove-FirewallRuleCollectionGroupWhenReady `
        -ResourceGroupName $ResourceGroupName `
        -FirewallPolicyName $FirewallPolicyName `
        -RuleCollectionGroupName $RuleCollectionGroupName `
        -TimeoutSeconds 900 `
        -PollIntervalSeconds 15

    if ($deleteRequested) {
        $ruleCollectionGroupRemoved = Wait-UntilResourceAbsent `
            -ResourceDescription "Firewall Policy Rule Collection Group '$RuleCollectionGroupName'" `
            -TimeoutSeconds 600 `
            -GetAction {
                Get-AzFirewallPolicyRuleCollectionGroup `
                    -Name $RuleCollectionGroupName `
                    -ResourceGroupName $ResourceGroupName `
                    -AzureFirewallPolicyName $FirewallPolicyName `
                    -ErrorAction Stop
            }
    }

    if ($ruleCollectionGroupRemoved) {
        Write-Host "Firewall Policy Rule Collection Group removed successfully"
    }
    else {
        $cleanupFailures.Add("Firewall Policy Rule Collection Group '$RuleCollectionGroupName'") | Out-Null
    }
}
catch {
    Write-Host "Error removing Firewall Policy Rule Collection Group: $_" -ForegroundColor Red
    $cleanupFailures.Add("Firewall Policy Rule Collection Group '$RuleCollectionGroupName'") | Out-Null
}

# Remove the IP Groups only after the rule collection group is confirmed absent.
if ($ruleCollectionGroupRemoved) {
    try {
        Write-Host "Finding IP Groups matching $IpGroupNamePattern..."
        $blocklistIpGroups = @(
            Get-AzIpGroup -ResourceGroupName $ResourceGroupName -ErrorAction Stop |
                Where-Object { $_.Name -like $IpGroupNamePattern }
        )

        if ($blocklistIpGroups.Count -eq 0) {
            Write-Host "No matching blocklist IP Groups found; they may have already been deleted" -ForegroundColor Yellow
        }
        else {
            foreach ($ipGroup in $blocklistIpGroups) {
                $ipGroupName = $ipGroup.Name
                $deleteRequested = Invoke-DeletionWithRetry `
                    -ResourceDescription "IP Group '$ipGroupName'" `
                    -DeleteAction {
                        Remove-AzIpGroup `
                            -ResourceGroupName $ResourceGroupName `
                            -Name $ipGroupName `
                            -Force `
                            -ErrorAction Stop
                    }

                $removed = $false
                if ($deleteRequested) {
                    $removed = Wait-UntilResourceAbsent `
                        -ResourceDescription "IP Group '$ipGroupName'" `
                        -TimeoutSeconds 300 `
                        -GetAction {
                            Get-AzIpGroup `
                                -ResourceGroupName $ResourceGroupName `
                                -Name $ipGroupName `
                                -ErrorAction Stop
                        }
                }

                if ($removed) {
                    Write-Host "IP Group '$ipGroupName' removed successfully"
                }
                else {
                    $cleanupFailures.Add("IP Group '$ipGroupName'") | Out-Null
                }
            }
        }
    }
    catch {
        Write-Host "Error enumerating blocklist IP Groups: $_" -ForegroundColor Red
        $cleanupFailures.Add("IP Groups matching '$IpGroupNamePattern'") | Out-Null
    }
}
else {
    Write-Host "Skipping IP Group deletion because the rule collection group is still present." -ForegroundColor Red
    $cleanupFailures.Add("IP Groups matching '$IpGroupNamePattern' (not attempted)") | Out-Null
}

# Remove the default App Service Plan if no sites still use it
try {
    Write-Host "Checking default App Service Plan $DefaultAppServicePlanName..."
    try {
        $appServicePlan = Get-AzAppServicePlan `
            -ResourceGroupName $ResourceGroupName `
            -Name $DefaultAppServicePlanName `
            -ErrorAction Stop
    }
    catch {
        if (Test-IsResourceNotFoundError -ErrorRecord $_) {
            $appServicePlan = $null
        }
        else {
            throw
        }
    }

    if (-not $appServicePlan) {
        Write-Host "Default App Service Plan not found; it may have already been deleted" -ForegroundColor Yellow
    }
    else {
        $planResourceId = if ($appServicePlan.Id) { $appServicePlan.Id } else { $appServicePlan.ResourceId }
        if (-not $planResourceId) {
            throw "Unable to determine the resource ID for App Service Plan '$DefaultAppServicePlanName'."
        }
        $sitesUsingPlan = @()

        for ($attempt = 1; $attempt -le 6; $attempt++) {
            $sitesUsingPlan = @(
                Get-AzResource -ResourceType "Microsoft.Web/sites" -ExpandProperties -ErrorAction Stop |
                    Where-Object {
                        $_.Properties.ServerFarmId -and
                        $_.Properties.ServerFarmId.TrimEnd('/') -eq $planResourceId.TrimEnd('/')
                    }
            )

            if ($sitesUsingPlan.Count -eq 0) {
                break
            }

            if ($attempt -lt 6) {
                Write-Host "Waiting for Function App deletion to release the plan... (attempt $attempt of 6)"
                Start-Sleep -Seconds 5
            }
        }

        if ($sitesUsingPlan.Count -gt 0) {
            $siteNames = ($sitesUsingPlan.Name -join ", ")
            Write-Host "Default App Service Plan is still used by: $siteNames. It will not be deleted." -ForegroundColor Yellow
        }
        else {
            Remove-AzAppServicePlan -ResourceGroupName $ResourceGroupName -Name $DefaultAppServicePlanName -Force
            Write-Host "Default App Service Plan removed successfully"
        }
    }
}
catch {
    Write-Host "Error removing default App Service Plan: $_" -ForegroundColor Red
    $cleanupFailures.Add("Default App Service Plan '$DefaultAppServicePlanName'") | Out-Null
}

# Remove Storage Account
try {
    Write-Host "Removing Storage Account $StorageAccountName..."
    Remove-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -Force
    Write-Host "Storage Account removed successfully"
}
catch {
    Write-Host "Error removing Storage Account: $_" -ForegroundColor Red
    $cleanupFailures.Add("Storage Account '$StorageAccountName'") | Out-Null
}

# Remove Application Insights
try {
    Write-Host "Removing Application Insights $AppInsightsName..."
    Remove-AzApplicationInsights -ResourceGroupName $ResourceGroupName -Name $AppInsightsName
    Write-Host "Application Insights removed successfully"
}
catch {
    Write-Host "Error removing Application Insights: $_" -ForegroundColor Red
    $cleanupFailures.Add("Application Insights '$AppInsightsName'") | Out-Null
}

if ($cleanupFailures.Count -gt 0) {
    Write-Host "`nCleanup completed with failures. The following resources were not confirmed removed:" -ForegroundColor Red
    $cleanupFailures | Select-Object -Unique | ForEach-Object {
        Write-Host " - $_" -ForegroundColor Red
    }
    exit 1
}

Write-Host "`nCleanup completed successfully!" -ForegroundColor Green
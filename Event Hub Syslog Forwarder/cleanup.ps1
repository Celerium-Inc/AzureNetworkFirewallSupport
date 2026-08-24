# Cleanup script for Event Hub Syslog Forwarder Function
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$FunctionAppName,

    [Parameter(Mandatory = $false)]
    [ValidateSet("AzurePublicCloud","AzureUSGovernment")]
    [string]$AzureCloud = "AzurePublicCloud"
)

# Error handling
$ErrorActionPreference = 'Stop'

# Helper function for timestamped logging
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Level = "Info"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
        default   { "White" }
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

# Helper function to generate valid storage account name
function Get-ValidStorageAccountName {
    param([string]$FunctionAppName)

    Write-Log "Generating storage account name from function app name: $FunctionAppName" -Level Info

    # Remove any special characters and convert to lowercase
    $name = $FunctionAppName.ToLower() -replace '[^a-z0-9]', ''
    Write-Log "After sanitization: $name" -Level Info

    # Append 'storage' to make it more descriptive
    $name = "${name}storage"

    # Ensure the name is no longer than 24 characters
    if ($name.Length -gt 24) {
        $originalName = $name
        $name = $name.Substring(0, 24)
        Write-Log "Truncated storage account name from $($originalName.Length) to 24 characters" -Level Info
    }

    Write-Log "Final storage account name: $name" -Level Info
    return $name
}

Write-Log "========================================" -Level Info
Write-Log "Event Hub Syslog Forwarder Cleanup" -Level Info
Write-Log "========================================" -Level Info
Write-Log "Resource Group: $ResourceGroupName" -Level Info
Write-Log "Function App: $FunctionAppName" -Level Info
Write-Log "Azure Cloud: $AzureCloud" -Level Info

# Generate storage account name
$StorageAccountName = Get-ValidStorageAccountName -FunctionAppName $FunctionAppName
Write-Log "Derived Storage Account: $StorageAccountName" -Level Info

# Generate Application Insights name
$AppInsightsName = "$FunctionAppName-insights"
Write-Log "Derived Application Insights: $AppInsightsName" -Level Info

# Derive the App Service Plan created by the default deployment
$DefaultAppServicePlanName = "$FunctionAppName-plan"

# Function to ensure we have a valid Azure context
function Ensure-AzureConnection {
    try {
        Write-Log "Checking Azure connection..." -Level Info

        $targetAzEnv = switch ($AzureCloud) {
            "AzureUSGovernment" { "AzureUSGovernment" }
            default             { "AzureCloud" }
        }
        Write-Log "Target Azure environment: $targetAzEnv" -Level Info

        $context = Get-AzContext
        if (-not $context) {
            Write-Log "No Azure context found. Connecting to $targetAzEnv..." -Level Warning
            Connect-AzAccount -UseDeviceAuthentication -Environment $targetAzEnv
            $context = Get-AzContext
        }
        elseif ($context.Environment.Name -ne $targetAzEnv) {
            Write-Log "Current Az environment ($($context.Environment.Name)) differs from target ($targetAzEnv). Switching..." -Level Warning
            Connect-AzAccount -UseDeviceAuthentication -Environment $targetAzEnv
            $context = Get-AzContext
        }
        else {
            Write-Log "Already connected to $targetAzEnv" -Level Success
        }

        if (-not $context) {
            throw "Failed to establish Azure connection"
        }

        Write-Log "Azure context verified - Account: $($context.Account.Id), Subscription: $($context.Subscription.Name)" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to connect to Azure: $_" -Level Error
        return $false
    }
}

# Ensure we're connected before proceeding
Write-Log "========================================" -Level Info
Write-Log "Verifying Azure Connection" -Level Info
Write-Log "========================================" -Level Info

if (-not (Ensure-AzureConnection)) {
    Write-Log "Cannot proceed without Azure connection" -Level Error
    exit 1
}

# Discover the attached plan before deleting the Function App. Only the generated
# default plan is assumed to be owned by this deployment; named plans are preserved.
Write-Log "Inspecting Function App hosting plan..." -Level Info
$functionApp = Get-AzFunctionApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -ErrorAction SilentlyContinue
$deleteDefaultAppServicePlan = $false
$attachedAppServicePlanName = $null
$attachedAppServicePlanResourceGroup = $null

if ($functionApp) {
    $attachedPlanId = $functionApp.ServerFarmId
    if (-not $attachedPlanId) {
        $functionAppResource = Get-AzResource `
            -ResourceGroupName $ResourceGroupName `
            -ResourceName $FunctionAppName `
            -ResourceType "Microsoft.Web/sites" `
            -ExpandProperties `
            -ErrorAction SilentlyContinue
        if ($functionAppResource -and $functionAppResource.Properties.ServerFarmId) {
            $attachedPlanId = $functionAppResource.Properties.ServerFarmId
        }
    }

    if ($attachedPlanId -match '(?i)/resourceGroups/([^/]+)/providers/Microsoft\.Web/serverfarms/([^/]+)/?$') {
        $attachedAppServicePlanResourceGroup = [Uri]::UnescapeDataString($Matches[1])
        $attachedAppServicePlanName = [Uri]::UnescapeDataString($Matches[2])

        if (
            $attachedAppServicePlanName -ieq $DefaultAppServicePlanName -and
            $attachedAppServicePlanResourceGroup -ieq $ResourceGroupName
        ) {
            $deleteDefaultAppServicePlan = $true
            Write-Log "Default App Service Plan deletion target: $attachedAppServicePlanName" -Level Info
        }
        else {
            Write-Log "Attached named App Service Plan will be preserved: $attachedAppServicePlanName (Resource Group: $attachedAppServicePlanResourceGroup)" -Level Info
        }
    }
    elseif ($attachedPlanId) {
        Write-Log "Unable to parse attached App Service Plan resource ID. The plan will be preserved: $attachedPlanId" -Level Warning
    }
    else {
        Write-Log "Unable to determine the attached App Service Plan. No plan will be deleted." -Level Warning
    }
}
else {
    Write-Log "Function App not found. No App Service Plan will be inferred or deleted." -Level Warning
}

$totalResources = if ($deleteDefaultAppServicePlan) { 4 } else { 3 }
Write-Log "Cleanup deletion targets: $totalResources" -Level Info
Write-Log "========================================" -Level Info

# Prompt for confirmation after determining the exact deletion targets
$planPrompt = if ($deleteDefaultAppServicePlan) { ", including its default App Service Plan" } else { "" }
$confirmation = Read-Host "Are you sure you want to delete these $totalResources resources$planPrompt? (y/n)"
if ($confirmation -ne 'y') {
    Write-Log "Cleanup cancelled by user" -Level Warning
    exit 0
}

Write-Log "User confirmed deletion - proceeding with cleanup" -Level Info

# Track deletion statistics
$deletionStats = @{
    Total = $totalResources
    Successful = 0
    Failed = 0
    NotFound = 0
}

Write-Log "========================================" -Level Info
Write-Log "Starting Resource Deletion" -Level Info
Write-Log "========================================" -Level Info

# Remove Function App
Write-Log "Step 1/$($totalResources): Removing Function App" -Level Info
try {
    Write-Log "Checking if Function App '$FunctionAppName' exists..." -Level Info

    if ($null -eq $functionApp) {
        Write-Log "Function App '$FunctionAppName' not found - may have been already deleted" -Level Warning
        $deletionStats.NotFound++
    }
    else {
        Write-Log "Function App found - initiating deletion..." -Level Info
        Write-Log "  Location: $($functionApp.Location)" -Level Info
        Write-Log "  Runtime: $($functionApp.Runtime)" -Level Info

        Remove-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -Force
        Write-Log "Function App '$FunctionAppName' removed successfully" -Level Success
        $deletionStats.Successful++
    }
}
catch {
    Write-Log "Error removing Function App '$FunctionAppName': $_" -Level Error
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    $deletionStats.Failed++
}

# Remove the default App Service Plan if no sites still use it
if ($deleteDefaultAppServicePlan) {
    Write-Log "Step 2/$($totalResources): Removing Default App Service Plan" -Level Info
    try {
        Write-Log "Checking if default App Service Plan '$DefaultAppServicePlanName' exists..." -Level Info
        $appServicePlan = Get-AzAppServicePlan -ResourceGroupName $ResourceGroupName -Name $DefaultAppServicePlanName -ErrorAction SilentlyContinue

        if ($null -eq $appServicePlan) {
            Write-Log "Default App Service Plan '$DefaultAppServicePlanName' not found - may have been already deleted" -Level Warning
            $deletionStats.NotFound++
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
                    Write-Log "Waiting for Function App deletion to release the plan... (attempt $attempt of 6)" -Level Info
                    Start-Sleep -Seconds 5
                }
            }

            if ($sitesUsingPlan.Count -gt 0) {
                $siteNames = ($sitesUsingPlan.Name -join ", ")
                Write-Log "Default App Service Plan is still used by: $siteNames. It will not be deleted." -Level Warning
                $deletionStats.Failed++
            }
            else {
                Remove-AzAppServicePlan -ResourceGroupName $ResourceGroupName -Name $DefaultAppServicePlanName -Force
                Write-Log "Default App Service Plan '$DefaultAppServicePlanName' removed successfully" -Level Success
                $deletionStats.Successful++
            }
        }
    }
    catch {
        Write-Log "Error removing default App Service Plan '$DefaultAppServicePlanName': $_" -Level Error
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Error
        $deletionStats.Failed++
    }
}

# Remove Storage Account
$storageStep = if ($deleteDefaultAppServicePlan) { 3 } else { 2 }
Write-Log "Step $storageStep/$($totalResources): Removing Storage Account" -Level Info
try {
    Write-Log "Checking if Storage Account '$StorageAccountName' exists..." -Level Info
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue

    if ($null -eq $storageAccount) {
        Write-Log "Storage Account '$StorageAccountName' not found - may have been already deleted" -Level Warning
        $deletionStats.NotFound++
    }
    else {
        Write-Log "Storage Account found - initiating deletion..." -Level Info
        Write-Log "  Location: $($storageAccount.Location)" -Level Info
        Write-Log "  SKU: $($storageAccount.Sku.Name)" -Level Info

        Remove-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -Force
        Write-Log "Storage Account '$StorageAccountName' removed successfully" -Level Success
        $deletionStats.Successful++
    }
}
catch {
    Write-Log "Error removing Storage Account '$StorageAccountName': $_" -Level Error
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    $deletionStats.Failed++
}

# Remove Application Insights
$appInsightsStep = if ($deleteDefaultAppServicePlan) { 4 } else { 3 }
Write-Log "Step $appInsightsStep/$($totalResources): Removing Application Insights" -Level Info
try {
    Write-Log "Checking if Application Insights '$AppInsightsName' exists..." -Level Info
    $appInsights = Get-AzApplicationInsights -ResourceGroupName $ResourceGroupName -Name $AppInsightsName -ErrorAction SilentlyContinue

    if ($null -eq $appInsights) {
        Write-Log "Application Insights '$AppInsightsName' not found - may have been already deleted" -Level Warning
        $deletionStats.NotFound++
    }
    else {
        Write-Log "Application Insights found - initiating deletion..." -Level Info
        Write-Log "  Location: $($appInsights.Location)" -Level Info
        Write-Log "  Instrumentation Key: $($appInsights.InstrumentationKey)" -Level Info

        Remove-AzApplicationInsights -ResourceGroupName $ResourceGroupName -Name $AppInsightsName
        Write-Log "Application Insights '$AppInsightsName' removed successfully" -Level Success
        $deletionStats.Successful++
    }
}
catch {
    Write-Log "Error removing Application Insights '$AppInsightsName': $_" -Level Error
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    $deletionStats.Failed++
}

# Final summary
Write-Log "========================================" -Level Info
Write-Log "Cleanup Summary" -Level Info
Write-Log "========================================" -Level Info
Write-Log "Total Resources: $($deletionStats.Total)" -Level Info
Write-Log "Successfully Deleted: $($deletionStats.Successful)" -Level Success
Write-Log "Not Found: $($deletionStats.NotFound)" -Level Warning
Write-Log "Failed: $($deletionStats.Failed)" -Level $(if ($deletionStats.Failed -gt 0) { "Error" } else { "Info" })
Write-Log "========================================" -Level Info

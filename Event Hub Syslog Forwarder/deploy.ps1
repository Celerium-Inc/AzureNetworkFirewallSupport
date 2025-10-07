# Deployment script for Event Hub Syslog Forwarder
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$Location,
    
    [Parameter(Mandatory = $true)]
    [string]$FunctionAppName,

    [Parameter(Mandatory = $true)]
    [string]$SyslogServer,

    [Parameter(Mandatory = $true)]
    [int]$SyslogPort,

    [Parameter(Mandatory = $true)]
    [string]$EventHubName,

    [Parameter(Mandatory = $true)]
    [string]$EventHubConnection,

    [Parameter(Mandatory = $false)]
    [ValidateSet("SSL", "UDP")]
    [string]$Protocol = "SSL",

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

# Verify Azure connection (environment-aware)
try {
    $targetAzEnv = switch ($AzureCloud) {
        "AzureUSGovernment" { "AzureUSGovernment" }
        default             { "AzureCloud" }
    }
    $context = Get-AzContext
    if (-not $context) {
        Write-Host "Please login to $targetAzEnv..."
        Connect-AzAccount -UseDeviceAuthentication -Environment $targetAzEnv
        $context = Get-AzContext
    } elseif ($context.Environment.Name -ne $targetAzEnv) {
        Write-Host "Current Az environment ($($context.Environment.Name)) differs from target ($targetAzEnv). Logging in to target..."
        Connect-AzAccount -UseDeviceAuthentication -Environment $targetAzEnv
        $context = Get-AzContext
    }
    Write-Host "Using subscription: $($context.Subscription.Name) ($($context.Subscription.Id)) in $targetAzEnv"
}
catch {
    Write-Host "Please login to $targetAzEnv..."
    Connect-AzAccount -UseDeviceAuthentication -Environment $targetAzEnv
}

# Verify Resource Group exists
Write-Host "Verifying Resource Group..."
$resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $resourceGroup) {
    throw "Resource Group '$ResourceGroupName' not found. Please specify an existing resource group."
}

# Generate storage account name from function app name
$StorageAccountName = Get-ValidStorageAccountName -FunctionAppName $FunctionAppName
Write-Host "Using storage account name: $StorageAccountName"

# Create Storage Account if it doesn't exist
Write-Host "Creating Storage Account..."
$storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-not $storageAccount) {
    $storageAccount = New-AzStorageAccount -ResourceGroupName $ResourceGroupName `
        -Name $StorageAccountName `
        -Location $Location `
        -SkuName Standard_LRS `
        -MinimumTlsVersion TLS1_2 `
        -EnableHttpsTrafficOnly $true
}

# Create Application Insights
Write-Host "Creating Application Insights..."
$appInsightsName = "$FunctionAppName-insights"
$appInsights = Get-AzApplicationInsights -ResourceGroupName $ResourceGroupName -Name $appInsightsName -ErrorAction SilentlyContinue
if (-not $appInsights) {
    $appInsights = New-AzApplicationInsights -ResourceGroupName $ResourceGroupName `
        -Name $appInsightsName `
        -Location $Location `
        -Kind web `
        -RetentionInDays 90
}

# Create Function App with Application Insights
Write-Host "Creating Function App..."

# Helper function for retrying operations
function Invoke-WithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 5,
        [int]$RetryDelaySeconds = 60
    )

    $attempt = 1
    $success = $false

    while (-not $success -and $attempt -le $MaxAttempts) {
        try {
            Write-Host "Attempt $attempt of $MaxAttempts..."
            $result = & $ScriptBlock
            $success = $true
            return $result
        }
        catch {
            if ($attempt -eq $MaxAttempts) {
                Write-Host "Final attempt failed. Error: $_" -ForegroundColor Red
                throw
            }
            Write-Host "Attempt $attempt failed. Retrying in $RetryDelaySeconds seconds... Error: $_" -ForegroundColor Yellow
            Start-Sleep -Seconds $RetryDelaySeconds
            $attempt++
        }
    }
}

# Check if Function App exists
$existingApp = Get-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if ($existingApp) {
    Write-Host "Updating existing Function App..."
    # For updating, we use a minimal set of parameters
    $functionApp = Invoke-WithRetry -ScriptBlock {
        Update-AzFunctionApp `
            -ResourceGroupName $ResourceGroupName `
            -Name $FunctionAppName
    }
} else {
    Write-Host "Creating new Function App..."
    # For new creation, we use the full set of parameters with consumption plan
    $functionApp = Invoke-WithRetry -ScriptBlock {
        New-AzFunctionApp `
            -ResourceGroupName $ResourceGroupName `
            -Name $FunctionAppName `
            -StorageAccountName $StorageAccountName `
            -Location $Location `
            -Runtime "PowerShell" `
            -RuntimeVersion "7.4" `
            -FunctionsVersion "4" `
            -OSType "Windows" `
            -ApplicationInsightsKey $appInsights.InstrumentationKey `
            -DisableApplicationInsights:$false
    }  
}

# Configure TLS and HTTPS settings using resource manager API
Write-Host "Configuring TLS and HTTPS settings..."
$functionAppResource = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceName $FunctionAppName -ResourceType "Microsoft.Web/sites"
$functionAppProperties = @{
    "httpsOnly" = $true
    "minTlsVersion" = "1.2"
}
Set-AzResource -ResourceId $functionAppResource.ResourceId -Properties $functionAppProperties -Force

# Configure runtime versions
Write-Host "Configuring runtime versions..."
$runtimeSettings = @{
    "FUNCTIONS_WORKER_RUNTIME" = "powershell"
    "FUNCTIONS_WORKER_RUNTIME_VERSION" = "7.4"
    "FUNCTIONS_EXTENSION_VERSION" = "~4"
    "WEBSITE_RUN_FROM_PACKAGE" = "0"  # Enable in-portal editing
    "WEBSITE_HTTPSONLY" = "1"  # Force HTTPS
}
Update-AzFunctionAppSetting -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -AppSetting $runtimeSettings

# Sync resource state
Write-Host "Syncing Function App state..."
$null = Get-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName

# Configure environment variables
Write-Host "Configuring environment variables..."
$settings = @{
    "SYSLOG_SERVER" = $SyslogServer
    "SYSLOG_PORT" = $SyslogPort
    "SYSLOG_PROTOCOL" = $Protocol
    "EVENT_HUB_NAME" = $EventHubName
    "EVENTHUB_CONNECTION" = $EventHubConnection
    "WEBSITE_RUN_FROM_PACKAGE" = "0"
    "APPLICATIONINSIGHTS_CONNECTION_STRING" = $appInsights.ConnectionString
    "APPINSIGHTS_INSTRUMENTATIONKEY" = $appInsights.InstrumentationKey
}

Update-AzFunctionAppSetting -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -AppSetting $settings

# Deploy function code
Write-Host "Deploying function code..."

try {
    # Get the script's directory
    $scriptPath = $PSScriptRoot
    if (-not $scriptPath) {
        $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    
    # Verify source files exist
    $srcPath = Join-Path $scriptPath "src"
    Write-Host "Source path: $srcPath"
    
    # Get publishing credentials
    $publishingCredentials = Invoke-AzResourceAction -ResourceGroupName $ResourceGroupName `
        -ResourceType Microsoft.Web/sites/config `
        -ResourceName "$FunctionAppName/publishingcredentials" `
        -Action list -Force

    $username = $publishingCredentials.Properties.PublishingUserName
    $password = $publishingCredentials.Properties.PublishingPassword
    $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($username):$($password)"))

    # Derive Kudu URL from default hostname to support sovereign clouds
    try {
        $webApp = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName
        $defaultHost = $webApp.DefaultHostName
    }
    catch { $defaultHost = $null }
    if ($defaultHost) {
        $kuduHost = ($defaultHost -replace '(^[^\.]+)\.', '$1.scm.')
        $apiUrl = "https://$kuduHost/api/vfs"
    } else {
        $apiUrl = "https://$FunctionAppName.scm.azurewebsites.net/api/vfs"
    }

    # Create function directory
    Write-Host "Creating function directory..."
    $null = Invoke-RestMethod -Uri "$apiUrl/site/wwwroot/EventHubTrigger/" `
        -Headers @{Authorization="Basic $base64Auth"} `
        -Method PUT

    # Upload each file individually with retries
    Write-Host "Uploading function files..."
    $maxRetries = 3
    $retryDelay = 5

    function Invoke-WithRetry {
        param(
            [string]$Uri,
            [string]$Method,
            [string]$ContentType,
            [string]$Body,
            [hashtable]$Headers
        )

        $attempt = 1
        while ($attempt -le $maxRetries) {
            try {
                return Invoke-RestMethod -Uri $Uri -Method $Method -ContentType $ContentType -Body $Body -Headers $Headers
            }
            catch {
                if ($attempt -eq $maxRetries) {
                    throw
                }
                Write-Host "Attempt $attempt failed, retrying in $retryDelay seconds..."
                Start-Sleep -Seconds $retryDelay
                $attempt++
            }
        }
    }
    
    # Upload function.json
    $functionJson = Get-Content -Path (Join-Path $srcPath "function.json") -Raw
    Invoke-WithRetry -Uri "$apiUrl/site/wwwroot/EventHubTrigger/function.json" `
        -Headers @{Authorization="Basic $base64Auth"} `
        -Method PUT `
        -Body $functionJson `
        -ContentType "application/json"

    # Upload run.ps1
    $runPs1 = Get-Content -Path (Join-Path $srcPath "run.ps1") -Raw
    Invoke-WithRetry -Uri "$apiUrl/site/wwwroot/EventHubTrigger/run.ps1" `
        -Headers @{Authorization="Basic $base64Auth"} `
        -Method PUT `
        -Body $runPs1 `
        -ContentType "text/plain"

    # Upload host.json to root
    $hostJson = Get-Content -Path (Join-Path $srcPath "host.json") -Raw
    Invoke-WithRetry -Uri "$apiUrl/site/wwwroot/host.json" `
        -Headers @{Authorization="Basic $base64Auth"} `
        -Method PUT `
        -Body $hostJson `
        -ContentType "application/json"

    Write-Host "Function code deployed successfully"
    
    # Restart the Function App
    Write-Host "Restarting Function App..."
    Restart-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -Force
}
catch {
    Write-Host "Failed to deploy function code: $_" -ForegroundColor Red
    throw
}

Write-Host "`nDeployment completed!"
Write-Host "`nFunction App Details:"
Write-Host "Name: $FunctionAppName"
if ($defaultHost) {
    Write-Host "URL: https://$defaultHost"
} else {
    Write-Host "URL: https://$FunctionAppName.azurewebsites.net"
}
Write-Host "Application Insights: $appInsightsName"
Write-Host "Syslog Server: $SyslogServer"
Write-Host "Syslog Port: $SyslogPort"
Write-Host "Protocol: $Protocol"
Write-Host "Event Hub Name: $EventHubName"
Write-Host "Event Hub Connection: [Hidden for security]"

Write-Host "`nSecurity Configurations:"
Write-Host "- HTTPS Only: Enabled"
Write-Host "- Minimum TLS Version: 1.2"
Write-Host "- Storage Account: HTTPS Traffic Only Enabled" 
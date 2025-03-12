# Deployment script for Event Hub Syslog Forwarder
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$Location,
    
    [Parameter(Mandatory = $true)]
    [string]$FunctionAppName,
    
    [Parameter(Mandatory = $true)]
    [string]$StorageAccountName,

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
    [string]$Protocol = "SSL"
)

# Error handling
$ErrorActionPreference = 'Stop'

# Verify Azure connection
try {
    $context = Get-AzContext
    if (-not $context) {
        Write-Host "Please login to Azure..."
        Connect-AzAccount -UseDeviceAuthentication
    }
    Write-Host "Using subscription: $($context.Subscription.Name) ($($context.Subscription.Id))"
}
catch {
    Write-Host "Please login to Azure..."
    Connect-AzAccount -UseDeviceAuthentication
}

# Verify Resource Group exists
Write-Host "Verifying Resource Group..."
$resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $resourceGroup) {
    throw "Resource Group '$ResourceGroupName' not found. Please specify an existing resource group."
}

# Create Storage Account
Write-Host "Creating Storage Account..."
$storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-not $storageAccount) {
    $storageAccount = New-AzStorageAccount -ResourceGroupName $ResourceGroupName `
        -Name $StorageAccountName `
        -Location $Location `
        -SkuName Standard_LRS
}

# Create Function App
Write-Host "Creating Function App..."
$functionApp = New-AzFunctionApp -ResourceGroupName $ResourceGroupName `
    -Name $FunctionAppName `
    -StorageAccountName $StorageAccountName `
    -Runtime PowerShell `
    -RuntimeVersion 7.2 `
    -FunctionsVersion 4 `
    -OSType Windows `
    -Location $Location

# Configure environment variables
Write-Host "Configuring environment variables..."
$settings = @{
    "SYSLOG_SERVER" = $SyslogServer
    "SYSLOG_PORT" = $SyslogPort
    "SYSLOG_PROTOCOL" = $Protocol
    "EVENT_HUB_NAME" = $EventHubName
    "EVENTHUB_CONNECTION" = $EventHubConnection
    "FUNCTIONS_WORKER_RUNTIME" = "powershell"
    "WEBSITE_RUN_FROM_PACKAGE" = "0"
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
    
    # Create the function in the portal
    $functionPath = "D:\home\site\wwwroot\EventHubTrigger"
    
    # Get publishing credentials
    $publishingCredentials = Invoke-AzResourceAction -ResourceGroupName $ResourceGroupName `
        -ResourceType Microsoft.Web/sites/config `
        -ResourceName "$FunctionAppName/publishingcredentials" `
        -Action list -Force

    $username = $publishingCredentials.Properties.PublishingUserName
    $password = $publishingCredentials.Properties.PublishingPassword
    $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($username):$($password)"))
    $apiUrl = "https://$FunctionAppName.scm.azurewebsites.net/api/vfs"

    # Create function directory
    Write-Host "Creating function directory..."
    Invoke-RestMethod -Uri "$apiUrl/site/wwwroot/EventHubTrigger/" `
        -Headers @{Authorization="Basic $base64Auth"} `
        -Method PUT

    # Upload each file individually
    Write-Host "Uploading function files..."
    
    # Upload function.json
    $functionJson = Get-Content -Path (Join-Path $srcPath "function.json") -Raw
    Invoke-RestMethod -Uri "$apiUrl/site/wwwroot/EventHubTrigger/function.json" `
        -Headers @{Authorization="Basic $base64Auth"} `
        -Method PUT `
        -Body $functionJson `
        -ContentType "application/json"

    # Upload run.ps1
    $runPs1 = Get-Content -Path (Join-Path $srcPath "forward-logs.ps1") -Raw
    Invoke-RestMethod -Uri "$apiUrl/site/wwwroot/EventHubTrigger/run.ps1" `
        -Headers @{Authorization="Basic $base64Auth"} `
        -Method PUT `
        -Body $runPs1 `
        -ContentType "text/plain"

    # Upload host.json to root
    $hostJson = Get-Content -Path (Join-Path $srcPath "host.json") -Raw
    Invoke-RestMethod -Uri "$apiUrl/site/wwwroot/host.json" `
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
Write-Host "URL: https://$FunctionAppName.azurewebsites.net"
Write-Host "Syslog Server: $SyslogServer"
Write-Host "Syslog Port: $SyslogPort"
Write-Host "Protocol: $Protocol"
Write-Host "Event Hub Name: $EventHubName"
Write-Host "Event Hub Connection: [Hidden for security]" 
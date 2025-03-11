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
    [string]$EventHubNamespace,

    [Parameter(Mandatory = $true)]
    [string]$EventHubName,

    [Parameter(Mandatory = $true)]
    [string]$SyslogServer,

    [Parameter(Mandatory = $true)]
    [int]$SyslogPort,

    [Parameter(Mandatory = $false)]
    [ValidateSet("SSL", "UDP")]
    [string]$Protocol = "SSL"
)

# Error handling
$ErrorActionPreference = 'Stop'

# Helper function to get publishing credentials
function Get-AzWebAppPublishingCredentials {
    param(
        [string]$ResourceGroupName,
        [string]$Name
    )
    
    $resourceType = "Microsoft.Web/sites/config"
    $resourceName = "$Name/publishingcredentials"
    
    Invoke-AzResourceAction `
        -ResourceGroupName $ResourceGroupName `
        -ResourceType $resourceType `
        -ResourceName $resourceName `
        -Action list `
        -Force
}

# Verify Azure connection
try {
    $context = Get-AzContext
    if (-not $context) {
        Write-Host "Please login to Azure..."
        Connect-AzAccount -UseDeviceAuthentication
    }
    $subscriptionId = $context.Subscription.Id
    Write-Host "Using subscription: $($context.Subscription.Name) ($subscriptionId)"
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

# Create Event Hub Namespace
Write-Host "Creating Event Hub Namespace..."
$ehNamespace = Get-AzEventHubNamespace -ResourceGroupName $ResourceGroupName -Name $EventHubNamespace -ErrorAction SilentlyContinue
if (-not $ehNamespace) {
    $ehNamespace = New-AzEventHubNamespace -ResourceGroupName $ResourceGroupName `
        -Name $EventHubNamespace `
        -Location $Location `
        -SkuName Standard
}

# Create Event Hub
Write-Host "Creating Event Hub..."
$eventHub = Get-AzEventHub -ResourceGroupName $ResourceGroupName -Namespace $EventHubNamespace -Name $EventHubName -ErrorAction SilentlyContinue
if (-not $eventHub) {
    $eventHub = New-AzEventHub -ResourceGroupName $ResourceGroupName `
        -Namespace $EventHubNamespace `
        -Name $EventHubName `
        -MessageRetentionInDays 1
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
    "EVENTHUB_CONNECTION" = (Get-AzEventHubKey -ResourceGroupName $ResourceGroupName `
        -Namespace $EventHubNamespace `
        -Name "RootManageSharedAccessKey").PrimaryConnectionString
    "SYSLOG_SERVER" = $SyslogServer
    "SYSLOG_PORT" = $SyslogPort
    "PROTOCOL" = $Protocol
}

Update-AzFunctionAppSetting -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -AppSetting $settings

# Deploy function code
Write-Host "Deploying function code..."

try {
    # Create temporary deployment folder
    $tempPath = Join-Path $env:TEMP "EventHubSyslogForwarder"
    New-Item -ItemType Directory -Path $tempPath -Force | Out-Null

    # Copy function files
    Copy-Item "src/forward-logs.ps1" -Destination "$tempPath/run.ps1"
    Copy-Item "src/function.json" -Destination "$tempPath/function.json"
    Copy-Item "src/host.json" -Destination "$tempPath/host.json"

    # Create zip file
    Compress-Archive -Path "$tempPath/*" -DestinationPath "$tempPath/function.zip" -Force

    # Get publishing credentials
    $publishingCredentials = Get-AzWebAppPublishingCredentials -ResourceGroupName $ResourceGroupName -Name $FunctionAppName
    $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $publishingCredentials.Properties.PublishingUserName, $publishingCredentials.Properties.PublishingPassword)))

    # Deploy using Kudu API
    $apiUrl = "https://$FunctionAppName.scm.azurewebsites.net/api/zipdeploy"
    $filePath = "$tempPath/function.zip"

    Invoke-RestMethod -Uri $apiUrl -Headers @{Authorization=("Basic {0}" -f $base64Auth)} -Method POST -InFile $filePath -ContentType "multipart/form-data"

    # Cleanup temporary files
    Remove-Item -Path $tempPath -Recurse -Force

    Write-Host "Function code deployed successfully"
}
catch {
    Write-Host "Failed to deploy function code: $_" -ForegroundColor Red
    throw
}

Write-Host "`nDeployment completed!"
Write-Host "`nFunction App Details:"
Write-Host "Name: $FunctionAppName"
Write-Host "URL: https://$FunctionAppName.azurewebsites.net"
Write-Host "Event Hub: $EventHubName"
Write-Host "Syslog Server: $SyslogServer"
Write-Host "Syslog Port: $SyslogPort"
Write-Host "Protocol: $Protocol" 
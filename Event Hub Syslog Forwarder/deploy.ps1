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
    [string]$Protocol = "SSL"
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

# Generate storage account name from function app name
$StorageAccountName = Get-ValidStorageAccountName -FunctionAppName $FunctionAppName
Write-Host "Using storage account name: $StorageAccountName"

# Create Storage Account
Write-Host "Creating Storage Account..."
$storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-not $storageAccount) {
    $storageAccount = New-AzStorageAccount -ResourceGroupName $ResourceGroupName `
        -Name $StorageAccountName `
        -Location $Location `
        -SkuName Standard_LRS
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
$functionAppParams = @{
    ResourceGroupName = $ResourceGroupName
    Name = $FunctionAppName
    StorageAccountName = $StorageAccountName
    SubscriptionId = $context.Subscription.Id
    Runtime = "PowerShell"
    OSType = "Windows"
    ApplicationInsightsKey = $appInsights.InstrumentationKey
    PlanType = "Consumption"
}

# Check if Function App exists
$existingApp = Get-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if ($existingApp) {
    Write-Host "Updating existing Function App..."
    $functionApp = Update-AzFunctionApp @functionAppParams
} else {
    Write-Host "Creating new Function App..."
    $functionApp = New-AzFunctionApp @functionAppParams
}

# Configure runtime versions
Write-Host "Configuring runtime versions..."
$runtimeSettings = @{
    "FUNCTIONS_WORKER_RUNTIME" = "powershell"
    "FUNCTIONS_WORKER_RUNTIME_VERSION" = "7.2"
    "FUNCTIONS_EXTENSION_VERSION" = "~4"
}
Update-AzFunctionAppSetting -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -AppSetting $runtimeSettings

# Force sync resource state
Write-Host "Syncing Function App state..."
$null = Get-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -Force

# Validate required permissions
Write-Host "Validating required permissions..."
$roles = @(
    @{
        Name = "Azure Event Hubs Data Receiver"
        Description = "Required for reading from Event Hub"
        Scope = "Microsoft.EventHub/namespaces"
    },
    @{
        Name = "Storage Blob Data Contributor"
        Description = "Required for Function App storage access"
        Scope = "Microsoft.Storage/storageAccounts"
    }
)

# Get the Function App's managed identity
$functionAppIdentity = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName
$objectId = $functionAppIdentity.Identity.PrincipalId

if (-not $objectId) {
    Write-Host "Warning: Function App managed identity not found. Enabling system-assigned managed identity..." -ForegroundColor Yellow
    $functionApp = Set-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -AssignIdentity $true
    $objectId = $functionApp.Identity.PrincipalId
}

# Check role assignments
$currentAssignments = Get-AzRoleAssignment -ObjectId $objectId -ResourceGroupName $ResourceGroupName
$missingRoles = @()

foreach ($role in $roles) {
    if (-not ($currentAssignments | Where-Object { $_.RoleDefinitionName -eq $role.Name })) {
        $missingRoles += $role
    }
}

if ($missingRoles.Count -gt 0) {
    Write-Host "Warning: Function App is missing the following required roles:" -ForegroundColor Yellow
    foreach ($role in $missingRoles) {
        Write-Host "- $($role.Name)" -ForegroundColor Yellow
        Write-Host "  Description: $($role.Description)" -ForegroundColor Yellow
        Write-Host "  Resource Type: $($role.Scope)" -ForegroundColor Yellow
    }
    Write-Host "`nSteps to assign roles:" -ForegroundColor Yellow
    Write-Host "1. Go to the Resource Group '$ResourceGroupName'" -ForegroundColor Yellow
    Write-Host "2. Click 'Access control (IAM)'" -ForegroundColor Yellow
    Write-Host "3. Click '+ Add' > 'Add role assignment'" -ForegroundColor Yellow
    Write-Host "4. Select the missing role" -ForegroundColor Yellow
    Write-Host "5. Select 'Managed identity' for Assign access to" -ForegroundColor Yellow
    Write-Host "6. Select the function app '$FunctionAppName'" -ForegroundColor Yellow
    Write-Host "7. Click 'Review + assign'" -ForegroundColor Yellow
    Write-Host "`nNote: The function may not work correctly until these roles are assigned." -ForegroundColor Yellow
}
else {
    Write-Host "Function App has all required roles." -ForegroundColor Green
}

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
    $runPs1 = Get-Content -Path (Join-Path $srcPath "run.ps1") -Raw
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
Write-Host "Application Insights: $appInsightsName"
Write-Host "Syslog Server: $SyslogServer"
Write-Host "Syslog Port: $SyslogPort"
Write-Host "Protocol: $Protocol"
Write-Host "Event Hub Name: $EventHubName"
Write-Host "Event Hub Connection: [Hidden for security]" 
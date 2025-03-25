# Deployment script for Azure Firewall Blocklist Integration Function
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$Location,
    
    [Parameter(Mandatory = $true)]
    [string]$FunctionAppName,

    [Parameter(Mandatory = $true)]
    [string]$FirewallPolicyName,

    [Parameter(Mandatory = $true)]
    [string]$FirewallName,

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [string]$ClientSecret,

    [Parameter(Mandatory = $true)]
    [string]$BlocklistUrl
)

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

# Error handling
$ErrorActionPreference = 'Stop'

# Login check and get subscription
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

# Check if Function App exists
$existingApp = Get-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if ($existingApp) {
    Write-Host "Updating existing Function App..."
    # For updating, we use a minimal set of parameters
    $functionApp = Update-AzFunctionApp `
        -ResourceGroupName $ResourceGroupName `
        -Name $FunctionAppName
} else {
    Write-Host "Creating new Function App..."
    # For new creation, we use the full set of parameters
    $functionApp = New-AzFunctionApp `
        -ResourceGroupName $ResourceGroupName `
        -Name $FunctionAppName `
        -StorageAccountName $StorageAccountName `
        -Location $Location `
        -Runtime "PowerShell" `
        -RuntimeVersion "7.2" `
        -FunctionsVersion "4" `
        -OSType "Windows" `
        -ApplicationInsightsKey $appInsights.InstrumentationKey
}

# Configure runtime versions
Write-Host "Configuring runtime versions..."
$runtimeSettings = @{
    "FUNCTIONS_WORKER_RUNTIME" = "powershell"
    "FUNCTIONS_WORKER_RUNTIME_VERSION" = "7.2"
    "FUNCTIONS_EXTENSION_VERSION" = "~4"
    "WEBSITE_RUN_FROM_PACKAGE" = "0"  # Enable in-portal editing
}
Update-AzFunctionAppSetting -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -AppSetting $runtimeSettings

# Force sync resource state
Write-Host "Syncing Function App state..."
$null = Get-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName

# Configure all environment variables
Write-Host "Configuring environment variables..."
$settings = @{
    "SUBSCRIPTION_ID" = $subscriptionId
    "RESOURCE_GROUP" = $ResourceGroupName
    "POLICY_NAME" = $FirewallPolicyName
    "RULE_COLLECTION_GROUP_NAME" = "CeleriumRuleCollectionGroup"
    "FIREWALL_NAME" = $FirewallName
    "TENANT_ID" = $TenantId
    "CLIENT_ID" = $ClientId
    "CLIENT_SECRET" = $ClientSecret
    "BLKLIST_URL" = $BlocklistUrl
    "APPLICATIONINSIGHTS_CONNECTION_STRING" = $appInsights.ConnectionString
    "APPINSIGHTS_INSTRUMENTATIONKEY" = $appInsights.InstrumentationKey
}

Update-AzFunctionAppSetting -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -AppSetting $settings

# Validate required roles for the service principal
Write-Host "Validating required roles for service principal..."
$roles = @(
    "Network Contributor",      # Required for managing network resources
    "Contributor"              # Required for managing IP Groups
)

$spRoles = Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName -ObjectId $ClientId
$missingRoles = @()

foreach ($roleName in $roles) {
    if (-not ($spRoles | Where-Object { $_.RoleDefinitionName -eq $roleName })) {
        $missingRoles += $roleName
    }
}

if ($missingRoles.Count -gt 0) {
    Write-Host "Warning: Service Principal is missing the following required roles:" -ForegroundColor Yellow
    foreach ($role in $missingRoles) {
        Write-Host "- $role" -ForegroundColor Yellow
    }
    Write-Host "Please assign these roles to the Service Principal (Client ID: $ClientId) in the Azure Portal." -ForegroundColor Yellow
    Write-Host "Steps to assign roles:" -ForegroundColor Yellow
    Write-Host "1. Go to the Resource Group '$ResourceGroupName'" -ForegroundColor Yellow
    Write-Host "2. Click 'Access control (IAM)'" -ForegroundColor Yellow
    Write-Host "3. Click '+ Add' > 'Add role assignment'" -ForegroundColor Yellow
    Write-Host "4. Select the missing role" -ForegroundColor Yellow
    Write-Host "5. Search for and select your service principal" -ForegroundColor Yellow
    Write-Host "6. Click 'Review + assign'" -ForegroundColor Yellow
}
else {
    Write-Host "Service Principal has all required roles." -ForegroundColor Green
}

# Deploy function code using Kudu API
Write-Host "Deploying function code..."
try {
    # Get publishing credentials
    $publishingCredentials = Get-AzWebAppPublishingCredentials -ResourceGroupName $ResourceGroupName -Name $FunctionAppName
    $username = $publishingCredentials.Properties.PublishingUserName
    $password = $publishingCredentials.Properties.PublishingPassword
    $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($username):$($password)"))

    # Create function directory structure
    $kuduApiUrl = "https://$FunctionAppName.scm.azurewebsites.net/api/vfs/site/wwwroot"
    
    # Create function directory
    Write-Host "Creating function directory..."
    $null = Invoke-RestMethod -Uri "$kuduApiUrl/blocklist/" `
        -Headers @{Authorization="Basic $base64Auth"} `
        -Method PUT

    # Upload function files
    Write-Host "Uploading function files..."
    
    # Upload function.json
    $functionJson = Get-Content -Path (Join-Path $PSScriptRoot "src/function.json") -Raw
    Invoke-RestMethod -Uri "$kuduApiUrl/blocklist/function.json" `
        -Headers @{
            Authorization = "Basic $base64Auth"
            "Content-Type" = "application/json"
        } -Method PUT -Body $functionJson

    # Upload run.ps1
    $runPs1 = Get-Content -Path (Join-Path $PSScriptRoot "src/run.ps1") -Raw
    Invoke-RestMethod -Uri "$kuduApiUrl/blocklist/run.ps1" `
        -Headers @{
            Authorization = "Basic $base64Auth"
            "Content-Type" = "text/plain"
        } -Method PUT -Body $runPs1

    # Upload host.json to root
    $hostJson = Get-Content -Path (Join-Path $PSScriptRoot "src/host.json") -Raw
    Invoke-RestMethod -Uri "$kuduApiUrl/host.json" `
        -Headers @{
            Authorization = "Basic $base64Auth"
            "Content-Type" = "application/json"
        } -Method PUT -Body $hostJson

    Write-Host "Function code deployed successfully"

    # Restart the Function App
    Write-Host "Restarting Function App..."
    Restart-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName
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

Write-Host "`nTo test the function:"
Write-Host "1. Get your function key from the Azure Portal > Function App > App Keys"
Write-Host "2. Test connectivity:"
Write-Host "   curl -X GET 'https://$FunctionAppName.azurewebsites.net/api/blocklist?code=<function_key>&action=test'"
Write-Host "3. Update blocklist:"
Write-Host "   curl -X GET 'https://$FunctionAppName.azurewebsites.net/api/blocklist?code=<function_key>&action=update'"
Write-Host "4. Unblock IPs:"
Write-Host "   curl -X POST 'https://$FunctionAppName.azurewebsites.net/api/blocklist?action=unblock&code=<function_key>' \\"
Write-Host "        -H 'Content-Type: application/json' \\"
Write-Host "        -d '{\"ips\":[\"1.1.1.1\",\"2.2.2.2\"]}'"

Write-Host "`nNext steps:"
Write-Host "1. Get your function key from the Azure Portal"
Write-Host "2. Test the deployment"
Write-Host "3. You can now edit the function code directly in the Azure Portal" 
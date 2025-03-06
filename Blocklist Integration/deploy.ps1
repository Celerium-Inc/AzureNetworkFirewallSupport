# Deployment script for Azure Firewall Blocklist Integration Function
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

# Create Storage Account if it doesn't exist
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
}

Update-AzFunctionAppSetting -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -AppSetting $settings

# Create the function
Write-Host "Creating function..."
$hostJson = Get-Content -Path (Join-Path $PSScriptRoot "src/host.json") -Raw
$functionJson = Get-Content -Path (Join-Path $PSScriptRoot "src/function.json") -Raw
$runPs1 = Get-Content -Path (Join-Path $PSScriptRoot "src/run.ps1") -Raw
$requirementsPsd1 = Get-Content -Path (Join-Path $PSScriptRoot "src/requirements.psd1") -Raw

# Get publishing credentials
$publishingCredentials = Invoke-AzResourceAction -ResourceGroupName $ResourceGroupName `
    -ResourceType Microsoft.Web/sites/config `
    -ResourceName "$FunctionAppName/publishingcredentials" `
    -Action list -Force

$username = $publishingCredentials.Properties.PublishingUserName
$password = $publishingCredentials.Properties.PublishingPassword
$base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($username):$($password)"))

try {
    # Create function files
    $kuduApiUrl = "https://$FunctionAppName.scm.azurewebsites.net/api/vfs/site/wwwroot"
    
    # Create host.json first
    Write-Host "Creating host.json..."
    Invoke-RestMethod -Uri "$kuduApiUrl/host.json" -Headers @{
        Authorization = "Basic $base64Auth"
        "Content-Type" = "application/json"
    } -Method Put -Body $hostJson


    # Create function files
    Write-Host "Creating function files..."
    $functionUrl = "$kuduApiUrl/blocklist"
    
    # Create function.json
    Invoke-RestMethod -Uri "$functionUrl/function.json" -Headers @{
        Authorization = "Basic $base64Auth"
        "Content-Type" = "application/json"
    } -Method Put -Body $functionJson

    # Create run.ps1
    Invoke-RestMethod -Uri "$functionUrl/run.ps1" -Headers @{
        Authorization = "Basic $base64Auth"
        "Content-Type" = "text/plain"
    } -Method Put -Body $runPs1

    # Create requirements.psd1
    Invoke-RestMethod -Uri "$functionUrl/requirements.psd1" -Headers @{
        Authorization = "Basic $base64Auth"
        "Content-Type" = "text/plain"
    } -Method Put -Body $requirementsPsd1

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

Write-Host "`nTo test the function:"
Write-Host "1. Get your function key from the Azure Portal > Function App > App Keys"
Write-Host "2. Test connectivity:"
Write-Host "   curl -X GET 'https://$FunctionAppName.azurewebsites.net/api/blocklist?code=<function_key>&action=test'"
Write-Host "3. Update blocklist:"
Write-Host "   curl -X GET 'https://$FunctionAppName.azurewebsites.net/api/blocklist?code=<function_key>&action=update'"
Write-Host "4. Unblock IPs:"
Write-Host "   curl -X GET 'https://$FunctionAppName.azurewebsites.net/api/blocklist?code=<function_key>&action=unblock&IPs=1.1.1.1,2.2.2.2'"

Write-Host "`nNext steps:"
Write-Host "1. Get your function key from the Azure Portal"
Write-Host "2. Test the deployment" 
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
    [string]$BlocklistUrl,

    [Parameter(Mandatory = $false)]
    [ValidateSet("AzurePublicCloud","AzureUSGovernment")]
    [string]$AzureCloud = "AzurePublicCloud",

    [Parameter(Mandatory = $false)]
    [string]$AuthorityHost,

    [Parameter(Mandatory = $false)]
    [string]$ArmEndpoint
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

# Login check and get subscription (environment-aware)
$targetAzEnv = switch ($AzureCloud) {
    "AzureUSGovernment" { "AzureUSGovernment" }
    default             { "AzureCloud" }
}
try {
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
    $subscriptionId = $context.Subscription.Id
    Write-Host "Using subscription: $($context.Subscription.Name) ($subscriptionId) in $targetAzEnv"
}
catch {
    Write-Host "Please login to $targetAzEnv..."
    Connect-AzAccount -UseDeviceAuthentication -Environment $targetAzEnv
    $context = Get-AzContext
    $subscriptionId = $context.Subscription.Id
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
        -RuntimeVersion "7.4" `
        -FunctionsVersion "4" `
        -OSType "Windows" `
        -ApplicationInsightsKey $appInsights.InstrumentationKey
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
    "ENFORCE_HTTPS_ONLY" = "true"  # Enforce HTTPS for all outbound connections
    "APPLICATIONINSIGHTS_CONNECTION_STRING" = $appInsights.ConnectionString
    "APPINSIGHTS_INSTRUMENTATIONKEY" = $appInsights.InstrumentationKey
    "AZURE_CLOUD" = $AzureCloud
    "AZURE_CLOUD_ENVIRONMENT" = $AzureCloud
}

# Add sovereign overrides if provided
if ($AuthorityHost) { $settings["AZURE_AUTHORITY_HOST"] = $AuthorityHost }
if ($ArmEndpoint) { $settings["AZURE_ARM_ENDPOINT"] = $ArmEndpoint }

Update-AzFunctionAppSetting -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -AppSetting $settings

# Deploy function code using Kudu API
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
    
    if (-not (Test-Path $srcPath)) {
        throw "Could not find source files in: $srcPath"
    }
    
    # Get publishing credentials
    $publishingCredentials = Get-AzWebAppPublishingCredentials -ResourceGroupName $ResourceGroupName -Name $FunctionAppName
    $username = $publishingCredentials.Properties.PublishingUserName
    $password = $publishingCredentials.Properties.PublishingPassword
    $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($username):$($password)"))

    # Create function directory structure
    # Derive Kudu host from the app's default hostname to support all clouds (public, gov)
    try {
        $webApp = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName
        $defaultHost = $webApp.DefaultHostName
    }
    catch {
        $defaultHost = $null
    }
    if ($defaultHost) {
        $kuduHost = ($defaultHost -replace '(^[^\.]+)\.', '$1.scm.')
        $kuduApiUrl = "https://$kuduHost/api/vfs/site/wwwroot"
    } else {
        # Fallback to public domain if default host is unavailable
        $kuduApiUrl = "https://$FunctionAppName.scm.azurewebsites.net/api/vfs/site/wwwroot"
    }
    
    # Function to upload file with retry
    function Invoke-FileUploadWithRetry {
        param(
            [string]$Uri,
            [string]$Content,
            [string]$ContentType,
            [int]$MaxRetries = 3
        )
        
        $retryCount = 0
        while ($retryCount -lt $MaxRetries) {
            try {
                # Try to upload the file directly first
                $response = Invoke-RestMethod -Uri $Uri `
                    -Headers @{
                        Authorization = "Basic $base64Auth"
                        "Content-Type" = $ContentType
                    } `
                    -Method PUT `
                    -Body $Content

                return $response
            }
            catch {
                if ($_.Exception.Response.StatusCode -eq 412 -and $retryCount -lt ($MaxRetries - 1)) {
                    $retryCount++
                    Write-Host "ETag conflict, retrying ($retryCount of $MaxRetries)..."
                    Start-Sleep -Seconds 2
                    continue
                }
                throw
            }
        }
    }

    # Create function directory
    Write-Host "Creating function directory..."
    try {
        $null = Invoke-RestMethod -Uri "$kuduApiUrl/blocklist/" `
            -Headers @{Authorization="Basic $base64Auth"} `
            -Method PUT
    }
    catch {
        if ($_.Exception.Response.StatusCode -ne 409) {  # Ignore "already exists" error
            throw
        }
    }

    # Upload function files
    Write-Host "Uploading function files..."
    
    # Upload files with retry logic
    Write-Host "Uploading function.json..."
    $functionJson = Get-Content -Path (Join-Path $srcPath "function.json") -Raw
    $null = Invoke-FileUploadWithRetry -Uri "$kuduApiUrl/blocklist/function.json" `
        -Content $functionJson `
        -ContentType "application/json"

    Write-Host "Uploading run.ps1..."
    $runPs1 = Get-Content -Path (Join-Path $srcPath "run.ps1") -Raw
    $null = Invoke-FileUploadWithRetry -Uri "$kuduApiUrl/blocklist/run.ps1" `
        -Content $runPs1 `
        -ContentType "text/plain"

    Write-Host "Uploading host.json..."
    $hostJson = Get-Content -Path (Join-Path $srcPath "host.json") -Raw
    $null = Invoke-FileUploadWithRetry -Uri "$kuduApiUrl/host.json" `
        -Content $hostJson `
        -ContentType "application/json"

    Write-Host "Function code deployed successfully"

    # Restart the Function App
    Write-Host "Restarting Function App..."
    Restart-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName
}
catch {
    Write-Host "Error deploying function code: $_" -ForegroundColor Red
    throw
}

Write-Host "`nDeployment completed!"
Write-Host "`nFunction App Details:"
Write-Host "Name: $FunctionAppName"
Write-Host "Application Insights: $appInsightsName"

Write-Host "`nSecurity Configurations:"
Write-Host "- HTTPS Only: Enabled"
Write-Host "- Minimum TLS Version: 1.2"
Write-Host "- Enforce HTTPS for blocklist URL: Enabled"

Write-Host "`nNext steps:"
Write-Host "1. Monitor the function execution in Application Insights"
Write-Host "2. Check the function logs in Azure Portal > Function App > Functions > blocklist > Monitor"
Write-Host "3. The function will automatically update the blocklist every 15 minutes" 
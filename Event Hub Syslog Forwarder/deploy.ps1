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
    [string]$AzureCloud = "AzurePublicCloud",

    # App Service Plan Parameters (OPTIONAL - will create Consumption plan if not provided)
    [Parameter(Mandatory = $false)]
    [string]$AppServicePlanName,

    [Parameter(Mandatory = $false)]
    [string]$AppServicePlanResourceGroup
)

# Error handling
$ErrorActionPreference = 'Stop'

# Set default App Service Plan Resource Group if not specified
if (-not $AppServicePlanResourceGroup) {
    $AppServicePlanResourceGroup = $ResourceGroupName
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

# Determine storage endpoint suffix based on cloud environment
$storageEndpointSuffix = switch ($AzureCloud) {
    "AzureUSGovernment" { "core.usgovcloudapi.net" }
    default             { "core.windows.net" }
}
Write-Host "Using storage endpoint suffix: $storageEndpointSuffix"

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

# Check if Application Insights already exists
$appInsights = Get-AzApplicationInsights -ResourceGroupName $ResourceGroupName -Name $appInsightsName -ErrorAction SilentlyContinue

if (-not $appInsights) {
    # Create new Application Insights instance
    $appInsights = New-AzApplicationInsights -ResourceGroupName $ResourceGroupName `
        -Name $appInsightsName `
        -Location $Location `
        -Kind web `
        -RetentionInDays 90
}

# Extract Application Insights properties using future-proof access pattern
# This approach works with both current and future module versions (v9.0.0+)
# Always try direct property access first, then fall back to Properties object
$appInsightsConnectionString = if ($appInsights.ConnectionString) {
    $appInsights.ConnectionString
} elseif ($appInsights.Properties.ConnectionString) {
    $appInsights.Properties.ConnectionString
} else {
    throw "Unable to retrieve Application Insights Connection String"
}

$appInsightsInstrumentationKey = if ($appInsights.InstrumentationKey) {
    $appInsights.InstrumentationKey
} elseif ($appInsights.Properties.InstrumentationKey) {
    $appInsights.Properties.InstrumentationKey
} else {
    throw "Unable to retrieve Application Insights Instrumentation Key"
}

Write-Host "Application Insights configured successfully" -ForegroundColor Green

# Create or verify App Service Plan
if (-not $AppServicePlanName) {
    # Generate default plan name from function app name
    $AppServicePlanName = "$FunctionAppName-plan"
    $AppServicePlanResourceGroup = $ResourceGroupName
    
    Write-Host "No App Service Plan specified. Creating default Consumption plan: $AppServicePlanName"
    
    $appServicePlan = Get-AzAppServicePlan -ResourceGroupName $AppServicePlanResourceGroup -Name $AppServicePlanName -ErrorAction SilentlyContinue
    
    # Check if plan exists and validate its SKU
    $needsCreation = $false
    
    if (-not $appServicePlan) {
        $needsCreation = $true
    } else {
        # Validate existing plan is suitable for Function Apps (not Free or Shared)
        $existingSku = $appServicePlan.Sku.Tier
        if ($existingSku -in @("Free", "Shared")) {
            Write-Host "Existing plan '$AppServicePlanName' has SKU '$existingSku' which doesn't support Function Apps." -ForegroundColor Yellow
            Write-Host "Deleting and recreating with Consumption (Y1) plan..." -ForegroundColor Yellow
            Remove-AzAppServicePlan -ResourceGroupName $AppServicePlanResourceGroup -Name $AppServicePlanName -Force
            $needsCreation = $true
        } else {
            Write-Host "Using existing plan: $AppServicePlanName (SKU: $existingSku)"
        }
    }
    
    if ($needsCreation) {
        # Create Consumption plan (Y1/Dynamic) using ARM API - works in both Azure Public and Azure Government clouds
        Write-Host "Creating Consumption plan (Y1) via ARM API..."
        
        $planProperties = @{
            reserved = $false  # Windows plan (set to $true for Linux)
        }
        
        $planSku = @{
            name = "Y1"
            tier = "Dynamic"
        }
        
        $appServicePlan = New-AzResource `
            -ResourceGroupName $AppServicePlanResourceGroup `
            -ResourceType "Microsoft.Web/serverfarms" `
            -ResourceName $AppServicePlanName `
            -Location $Location `
            -Properties $planProperties `
            -Sku $planSku `
            -Force `
            -ErrorAction Stop
        
        # Refresh the plan object to get full details
        $appServicePlan = Get-AzAppServicePlan -ResourceGroupName $AppServicePlanResourceGroup -Name $AppServicePlanName
        
        Write-Host "Created Consumption plan: $AppServicePlanName" -ForegroundColor Green
    }
} else {
    # Verify the explicitly provided App Service Plan exists
    Write-Host "Verifying App Service Plan: $AppServicePlanName"
    
    $appServicePlan = Get-AzAppServicePlan -ResourceGroupName $AppServicePlanResourceGroup -Name $AppServicePlanName -ErrorAction SilentlyContinue
    
    if (-not $appServicePlan) {
        throw "App Service Plan '$AppServicePlanName' not found in resource group '$AppServicePlanResourceGroup'. Please create the App Service Plan first or specify an existing plan."
    }
}

Write-Host "  Plan Name: $AppServicePlanName"
Write-Host "  Resource Group: $AppServicePlanResourceGroup"
Write-Host "  SKU: $($appServicePlan.Sku.Name)"
Write-Host "  Tier: $($appServicePlan.Sku.Tier)"
Write-Host "  Location: $($appServicePlan.Location)"

# Create Function App with Application Insights
Write-Host "Creating Function App..."

# Check if Function App exists
$existingApp = Get-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue

if ($existingApp) {
    Write-Host "Function App already exists. Updating configuration..."
    $functionApp = Update-AzFunctionApp `
        -ResourceGroupName $ResourceGroupName `
        -Name $FunctionAppName
} else {
    Write-Host "Creating new Function App..."
    Write-Host "  Name: $FunctionAppName"
    Write-Host "  Plan: $AppServicePlanName"
    Write-Host "  Storage: $StorageAccountName"
    Write-Host "  Runtime: PowerShell 7.4"

    # Check if plan is Flex Consumption (requires special handling)
    if ($appServicePlan.Sku.Tier -eq "FlexConsumption") {
        Write-Host "Detected Flex Consumption plan - using ARM template deployment..." -ForegroundColor Yellow
        Write-Host "Note: Flex Consumption plans require Linux hosting and instance memory configuration" -ForegroundColor Yellow

        # Flex Consumption requires ARM template or REST API deployment with functionAppConfig
        # Using New-AzResource for direct ARM deployment
        # Note: Flex Consumption does NOT allow FUNCTIONS_WORKER_RUNTIME* in siteConfig.appSettings
        # Runtime settings go in functionAppConfig.runtime instead
        $functionAppProperties = @{
            serverFarmId = $appServicePlan.Id
            siteConfig = @{
                appSettings = @(
                    @{ name = "AzureWebJobsStorage"; value = "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$((Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName)[0].Value);EndpointSuffix=$storageEndpointSuffix" }
                    @{ name = "APPLICATIONINSIGHTS_CONNECTION_STRING"; value = $appInsightsConnectionString }
                    @{ name = "APPINSIGHTS_INSTRUMENTATIONKEY"; value = $appInsightsInstrumentationKey }
                )
            }
            functionAppConfig = @{
                deployment = @{
                    storage = @{
                        type = "blobContainer"
                        value = "https://$StorageAccountName.blob.$storageEndpointSuffix/deployments"
                        authentication = @{
                            type = "StorageAccountConnectionString"
                            storageAccountConnectionStringName = "AzureWebJobsStorage"
                        }
                    }
                }
                scaleAndConcurrency = @{
                    maximumInstanceCount = 100
                    instanceMemoryMB = 2048
                }
                runtime = @{
                    name = "powershell"
                    version = "7.4"
                }
            }
        }

        try {
            Write-Host "Creating Flex Consumption Function App via ARM..."
            $functionApp = New-AzResource `
                -ResourceGroupName $ResourceGroupName `
                -ResourceType "Microsoft.Web/sites" `
                -ResourceName $FunctionAppName `
                -Location $Location `
                -Properties $functionAppProperties `
                -Kind "functionapp,linux" `
                -Force

            Write-Host "Function App created successfully with Flex Consumption plan" -ForegroundColor Green

            # Get the created function app
            Start-Sleep -Seconds 10
            $functionApp = Get-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName
        }
        catch {
            Write-Host "ARM deployment failed, attempting alternative method..." -ForegroundColor Yellow
            Write-Host "Error: $_" -ForegroundColor Yellow

            # Fallback: Try using Az.Functions module which may have been updated
            try {
                $functionApp = New-AzFunctionApp `
                    -ResourceGroupName $ResourceGroupName `
                    -Name $FunctionAppName `
                    -StorageAccountName $StorageAccountName `
                    -PlanName $AppServicePlanName `
                    -Runtime "PowerShell" `
                    -RuntimeVersion "7.4" `
                    -FunctionsVersion "4" `
                    -OSType "Linux" `
                    -ApplicationInsightsKey $appInsightsInstrumentationKey `
                    -ErrorAction Stop

                Write-Host "Function App created successfully using Az.Functions module" -ForegroundColor Green
            }
            catch {
                Write-Host "Both ARM and Az.Functions methods failed for Flex Consumption" -ForegroundColor Red
                Write-Host "Error: $_" -ForegroundColor Red
                throw "Unable to create Function App on Flex Consumption plan. This may require manual creation in the Azure Portal or using the latest Azure CLI version."
            }
        }
    }
    else {
        # Standard plans (Consumption, Basic, Premium) use Az.Functions module
        try {
            # Check if this is a Consumption plan (Dynamic tier)
            $isConsumption = $appServicePlan.Sku.Tier -eq "Dynamic"

            if ($isConsumption) {
                Write-Host "Detected Consumption plan (Y1) - using ARM deployment..." -ForegroundColor Yellow

                # Consumption plans have issues with New-AzFunctionApp trying to set AlwaysOn
                # Use ARM API like we do for Flex Consumption, but for Windows
                $functionAppProperties = @{
                    serverFarmId = $appServicePlan.Id
                    siteConfig = @{
                        appSettings = @(
                            @{ name = "AzureWebJobsStorage"; value = "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$((Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName)[0].Value);EndpointSuffix=$storageEndpointSuffix" }
                            @{ name = "FUNCTIONS_WORKER_RUNTIME"; value = "powershell" }
                            @{ name = "FUNCTIONS_WORKER_RUNTIME_VERSION"; value = "7.4" }
                            @{ name = "FUNCTIONS_EXTENSION_VERSION"; value = "~4" }
                            @{ name = "APPLICATIONINSIGHTS_CONNECTION_STRING"; value = $appInsightsConnectionString }
                            @{ name = "APPINSIGHTS_INSTRUMENTATIONKEY"; value = $appInsightsInstrumentationKey }
                        )
                        powerShellVersion = "7.4"
                    }
                }

                $functionApp = New-AzResource `
                    -ResourceGroupName $ResourceGroupName `
                    -ResourceType "Microsoft.Web/sites" `
                    -ResourceName $FunctionAppName `
                    -Location $Location `
                    -Properties $functionAppProperties `
                    -Kind "functionapp" `
                    -Force

                Write-Host "Function App created successfully with Consumption plan" -ForegroundColor Green
                Start-Sleep -Seconds 10
            }
            else {
                # Dedicated/Premium plans
                $functionApp = New-AzFunctionApp `
                    -ResourceGroupName $ResourceGroupName `
                    -Name $FunctionAppName `
                    -StorageAccountName $StorageAccountName `
                    -PlanName $AppServicePlanName `
                    -Runtime "PowerShell" `
                    -RuntimeVersion "7.4" `
                    -FunctionsVersion "4" `
                    -OSType "Windows" `
                    -ApplicationInsightsKey $appInsightsInstrumentationKey `
                    -ErrorAction Stop
            }

            Write-Host "Function App created successfully" -ForegroundColor Green

            # Wait for Function App to be fully created before configuring
            Write-Host "Waiting for Function App to be fully created..."
            Start-Sleep -Seconds 30
        }
        catch {
            Write-Host "Error creating Function App: $_" -ForegroundColor Red
            throw
        }
    }
}

# Wait for Function App resource to be accessible
Write-Host "Verifying Function App is accessible..."
$retryCount = 0
$maxRetries = 10
$functionAppResource = $null

while ($retryCount -lt $maxRetries -and -not $functionAppResource) {
    try {
        $functionAppResource = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceName $FunctionAppName -ResourceType "Microsoft.Web/sites" -ErrorAction Stop
        Write-Host "Function App resource is accessible"
    }
    catch {
        $retryCount++
        if ($retryCount -lt $maxRetries) {
            Write-Host "Function App not accessible yet, waiting... (attempt $retryCount of $maxRetries)"
            Start-Sleep -Seconds 10
        }
        else {
            throw "Function App resource not accessible after $maxRetries attempts: $_"
        }
    }
}

# Configure TLS and HTTPS settings using resource manager API
Write-Host "Configuring TLS and HTTPS settings..."
$functionAppProperties = @{
    "httpsOnly" = $true
    "minTlsVersion" = "1.2"
}
Set-AzResource -ResourceId $functionAppResource.ResourceId -Properties $functionAppProperties -Force

# Wait for Function App to be fully provisioned before configuring settings
Write-Host "Waiting for Function App to be fully provisioned..."
$maxWaitTime = 300  # 5 minutes
$waitInterval = 10  # 10 seconds
$elapsed = 0

while ($elapsed -lt $maxWaitTime) {
    $functionApp = Get-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if ($functionApp -and $functionApp.State -eq "Running") {
        Write-Host "Function App is running and ready"
        break
    }
    Write-Host "Waiting for Function App to be ready... ($elapsed seconds elapsed)"
    Start-Sleep -Seconds $waitInterval
    $elapsed += $waitInterval
}

if ($elapsed -ge $maxWaitTime) {
    Write-Host "Warning: Function App may not be fully ready, but proceeding with deployment" -ForegroundColor Yellow
}

# Enable system-assigned managed identity (Defender for Cloud recommendation)
Write-Host "Enabling system-assigned managed identity..."
try {
    $identityParams = @{
        Name              = $FunctionAppName
        ResourceGroupName = $ResourceGroupName
        Force             = $true
        ErrorAction       = "Stop"
    }
    $updateCmd = Get-Command Update-AzFunctionApp -ErrorAction Stop
    if ($updateCmd.Parameters.ContainsKey("EnableSystemAssignedIdentity")) {
        Update-AzFunctionApp @identityParams -EnableSystemAssignedIdentity $true
    }
    elseif ($updateCmd.Parameters.ContainsKey("IdentityType")) {
        Update-AzFunctionApp @identityParams -IdentityType SystemAssigned
    }
    else {
        Set-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -AssignIdentity $true -ErrorAction Stop | Out-Null
    }

    $identityApp = Get-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    $principalId = $null
    if ($identityApp) {
        if ($identityApp.PSObject.Properties["IdentityPrincipalId"]) {
            $principalId = $identityApp.IdentityPrincipalId
        }
        elseif ($identityApp.Identity -and $identityApp.Identity.PrincipalId) {
            $principalId = $identityApp.Identity.PrincipalId
        }
    }
    if ($principalId) {
        Write-Host "System-assigned managed identity enabled (PrincipalId: $principalId)" -ForegroundColor Green
    }
    else {
        Write-Host "System-assigned managed identity enabled" -ForegroundColor Green
    }
}
catch {
    Write-Host "Warning: Could not enable system-assigned managed identity: $_" -ForegroundColor Yellow
    Write-Host "Enable it manually: Function App > Identity > System assigned > On" -ForegroundColor Yellow
}

# Configure runtime versions with retry logic
Write-Host "Configuring runtime versions..."
$runtimeSettings = @{
    "FUNCTIONS_WORKER_RUNTIME" = "powershell"
    "FUNCTIONS_WORKER_RUNTIME_VERSION" = "7.4"
    "FUNCTIONS_EXTENSION_VERSION" = "~4"
    "WEBSITE_RUN_FROM_PACKAGE" = "0"  # Enable in-portal editing
    "WEBSITE_HTTPSONLY" = "1"  # Force HTTPS
}

$retryCount = 0
$maxRetries = 5
while ($retryCount -lt $maxRetries) {
    try {
        Update-AzFunctionAppSetting -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -AppSetting $runtimeSettings -ErrorAction Stop
        Write-Host "Runtime versions configured successfully" -ForegroundColor Green
        break
    }
    catch {
        $retryCount++
        if ($retryCount -lt $maxRetries) {
            Write-Host "Failed to update settings (attempt $retryCount of $maxRetries). Retrying in 15 seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds 15
        }
        else {
            Write-Host "Warning: Could not configure runtime settings after $maxRetries attempts. Continuing..." -ForegroundColor Yellow
        }
    }
}

# Additional wait for Kudu/SCM site to be ready
Write-Host "Waiting additional 30 seconds for Kudu/SCM site to be ready..."
Start-Sleep -Seconds 30

# Configure environment variables
Write-Host "Configuring environment variables..."
$settings = @{
    "SYSLOG_SERVER" = $SyslogServer
    "SYSLOG_PORT" = $SyslogPort
    "SYSLOG_PROTOCOL" = $Protocol
    "EVENT_HUB_NAME" = $EventHubName
    "EVENTHUB_CONNECTION" = $EventHubConnection
    "WEBSITE_RUN_FROM_PACKAGE" = "0"
    "APPLICATIONINSIGHTS_CONNECTION_STRING" = $appInsightsConnectionString
    "APPINSIGHTS_INSTRUMENTATIONKEY" = $appInsightsInstrumentationKey
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

    # Check if this is a Flex Consumption app (requires zip deployment)
    $isFlexConsumption = $appServicePlan.Sku.Tier -eq "FlexConsumption"

    if ($isFlexConsumption) {
        Write-Host "Flex Consumption plan detected - using zip deployment..." -ForegroundColor Yellow

        # Create a temporary directory for the deployment package
        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "funcapp-$(Get-Random)"
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

        # Create the function structure
        $funcDir = Join-Path $tempDir "EventHubTrigger"
        New-Item -ItemType Directory -Path $funcDir -Force | Out-Null

        # Copy function files
        Copy-Item -Path (Join-Path $srcPath "function.json") -Destination $funcDir
        Copy-Item -Path (Join-Path $srcPath "run.ps1") -Destination $funcDir
        Copy-Item -Path (Join-Path $srcPath "host.json") -Destination $tempDir

        # Create zip file
        $zipPath = Join-Path ([System.IO.Path]::GetTempPath()) "funcapp-$(Get-Random).zip"
        Write-Host "Creating deployment package: $zipPath"

        if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
            Compress-Archive -Path "$tempDir\*" -DestinationPath $zipPath -Force
        } else {
            throw "Compress-Archive cmdlet not available. Cannot create deployment package."
        }

        # Deploy using zip deployment
        Write-Host "Deploying function app package..."
        Publish-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -ArchivePath $zipPath -Force

        # Cleanup
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue

        Write-Host "Function code deployed successfully via zip deployment" -ForegroundColor Green
    }
    else {
        # Standard plans use Kudu VFS API
        # Get publishing credentials
    $publishingCredentials = Invoke-AzResourceAction -ResourceGroupName $ResourceGroupName `
        -ResourceType Microsoft.Web/sites/config `
        -ResourceName "$FunctionAppName/publishingcredentials" `
        -Action list -Force

    $username = $publishingCredentials.Properties.PublishingUserName
    $password = $publishingCredentials.Properties.PublishingPassword
    $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($username):$($password)"))

    # Derive Kudu URL from Function App properties to support sovereign clouds
    try {
        $functionAppDetails = Get-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        $defaultHost = $functionAppDetails.DefaultHostName
    }
    catch {
        Write-Host "Warning: Could not retrieve Function App details, using fallback URL" -ForegroundColor Yellow
        $defaultHost = $null
    }

    if ($defaultHost) {
        # Derive Kudu hostname from default hostname (e.g., app.azurewebsites.us -> app.scm.azurewebsites.us)
        $kuduHost = ($defaultHost -replace '(^[^\.]+)\.', '$1.scm.')
        $apiUrl = "https://$kuduHost/api/vfs"
        Write-Host "Using Kudu API URL: $apiUrl"
    } else {
        # Fallback to public cloud default
        $apiUrl = "https://$FunctionAppName.scm.azurewebsites.net/api/vfs"
        Write-Host "Using default Kudu API URL: $apiUrl"
    }

    # Test Kudu API accessibility before attempting file uploads
    Write-Host "Testing Kudu API accessibility..."
    try {
        $testResponse = Invoke-RestMethod -Uri "$apiUrl/site/wwwroot/" `
            -Headers @{Authorization="Basic $base64Auth"} `
            -Method GET `
            -ErrorAction Stop
        Write-Host "Kudu API is accessible" -ForegroundColor Green
    }
    catch {
        Write-Host "Warning: Kudu API test failed. This may indicate the site is still initializing." -ForegroundColor Yellow
        Write-Host "Waiting additional 60 seconds..."
        Start-Sleep -Seconds 60
    }

    # Note: Kudu VFS API creates directories automatically when files are uploaded
    Write-Host "Preparing to upload function files..."

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
                Write-Host "Uploading to: $Uri" -ForegroundColor Gray
                # Add If-Match header to handle ETag conflicts (overwrite regardless of ETag)
                $uploadHeaders = $Headers.Clone()
                $uploadHeaders["If-Match"] = "*"
                return Invoke-RestMethod -Uri $Uri -Method $Method -ContentType $ContentType -Body $Body -Headers $uploadHeaders
            }
            catch {
                $statusCode = $_.Exception.Response.StatusCode.value__
                $statusDesc = $_.Exception.Response.StatusCode
                Write-Host "Attempt $attempt failed: $statusCode $statusDesc" -ForegroundColor Yellow

                if ($attempt -eq $maxRetries) {
                    Write-Host "Failed to upload after $maxRetries attempts" -ForegroundColor Red
                    Write-Host "URI: $Uri" -ForegroundColor Red
                    Write-Host "Error: $_" -ForegroundColor Red
                    throw
                }
                Write-Host "Retrying in $retryDelay seconds..."
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
    }

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
Write-Host "- Extension Bundle: v4.x (latest)" 
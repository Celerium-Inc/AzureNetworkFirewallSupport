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

    # Auto = infer an existing named plan; otherwise FlexConsumption in Azure Public or Classic Basic B1 in Azure Government.
    # Classic = existing Windows Consumption/Premium/Dedicated flow.
    # FlexConsumption = create Linux Flex Function App (one app per plan; not an in-place migrate).
    [Parameter(Mandatory = $false)]
    [ValidateSet("Auto", "Classic", "FlexConsumption")]
    [string]$HostingPlan = "Auto",

    # Used only when HostingPlan is FlexConsumption (512, 2048, or 4096)
    [Parameter(Mandatory = $false)]
    [ValidateSet(512, 2048, 4096)]
    [int]$FlexInstanceMemoryMB = 512,

    # App Service Plan Parameters (OPTIONAL - Auto infers an existing named plan; otherwise Public uses Flex and Gov uses Classic B1)
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

$requestedHostingPlan = $HostingPlan

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

# Creates a Flex plan while tolerating transient ARM locks and eventual consistency.
function New-FlexConsumptionPlanWithRetry {
    param(
        [string]$ResourceGroupName,
        [string]$Name,
        [string]$Location,
        [int]$MaxAttempts = 6,
        [int]$InitialDelaySeconds = 5
    )

    function Assert-FlexPlan {
        param($Plan)

        if (-not $Plan) {
            return $null
        }

        $tier = $Plan.Sku.Tier
        $skuName = $Plan.Sku.Name
        if ($tier -ne "FlexConsumption" -or ($skuName -and $skuName -ne "FC1")) {
            throw "App Service Plan '$Name' exists but is SKU '$skuName/$tier', not FC1/FlexConsumption."
        }

        return $Plan
    }

    $planProperties = @{
        reserved = $true  # Linux required for Flex
    }
    $planSku = @{
        name     = "FC1"
        tier     = "FlexConsumption"
        family   = "FC"
        capacity = 0
    }
    $lastError = $null

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $existingPlan = Get-AzAppServicePlan -ResourceGroupName $ResourceGroupName -Name $Name -ErrorAction SilentlyContinue
        if ($existingPlan) {
            Write-Host "Flex Consumption plan is available: $Name" -ForegroundColor Green
            return (Assert-FlexPlan -Plan $existingPlan)
        }

        try {
            Write-Host "Creating Flex Consumption plan (attempt $attempt/$MaxAttempts)..."
            New-AzResource `
                -ResourceGroupName $ResourceGroupName `
                -ResourceType "Microsoft.Web/serverfarms" `
                -ResourceName $Name `
                -Location $Location `
                -Kind "functionapp" `
                -Properties $planProperties `
                -Sku $planSku `
                -Force `
                -ErrorAction Stop | Out-Null
        }
        catch {
            $lastError = $_

            # A failed response can still leave a successfully created plan behind.
            $existingPlan = Get-AzAppServicePlan -ResourceGroupName $ResourceGroupName -Name $Name -ErrorAction SilentlyContinue
            if ($existingPlan) {
                Write-Host "Azure created the Flex Consumption plan despite the failed create response." -ForegroundColor Yellow
                return (Assert-FlexPlan -Plan $existingPlan)
            }

            $errorText = @(
                $_.Exception.Message
                $_.ErrorDetails.Message
                ($_ | Out-String)
            ) -join "`n"
            $isTransientLock = $errorText -match '(?i)(\b429\b|59207|exclusive lock|too many requests|throttl)'
            if (-not $isTransientLock) {
                throw
            }

            if ($attempt -eq $MaxAttempts) {
                break
            }

            $delaySeconds = [Math]::Min(
                [int]($InitialDelaySeconds * [Math]::Pow(2, $attempt - 1)),
                60
            )
            Write-Host "Azure is locking or throttling the server farm. Retrying in ${delaySeconds}s..." -ForegroundColor Yellow
            Start-Sleep -Seconds $delaySeconds
            continue
        }

        # New-AzResource is synchronous, but the plan can take a few seconds to appear via Get-AzAppServicePlan.
        for ($readAttempt = 1; $readAttempt -le 6; $readAttempt++) {
            $createdPlan = Get-AzAppServicePlan -ResourceGroupName $ResourceGroupName -Name $Name -ErrorAction SilentlyContinue
            if ($createdPlan) {
                return (Assert-FlexPlan -Plan $createdPlan)
            }
            Start-Sleep -Seconds 2
        }

        if ($attempt -lt $MaxAttempts) {
            Write-Host "Plan create returned successfully but is not visible yet. Retrying verification..." -ForegroundColor Yellow
        }
    }

    # Give an accepted create one final chance to become visible before failing.
    Start-Sleep -Seconds 5
    $existingPlan = Get-AzAppServicePlan -ResourceGroupName $ResourceGroupName -Name $Name -ErrorAction SilentlyContinue
    if ($existingPlan) {
        return (Assert-FlexPlan -Plan $existingPlan)
    }

    $lastDetail = if ($lastError) { $lastError.Exception.Message } else { "The plan did not become visible after creation." }
    throw "Failed to create Flex Consumption plan '$Name' after $MaxAttempts attempts. Last error: $lastDetail"
}

# Flex-safe app settings update (Update-AzFunctionAppSetting is unreliable on Flex)
function Set-FunctionAppSettingsViaArm {
    param(
        [string]$ResourceGroupName,
        [string]$FunctionAppName,
        [hashtable]$Settings
    )

    $site = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceName $FunctionAppName -ResourceType "Microsoft.Web/sites" -ErrorAction Stop
    $listResult = Invoke-AzRestMethod -Path "$($site.ResourceId)/config/appsettings/list?api-version=2023-12-01" -Method POST -ErrorAction Stop
    $props = @{}
    if ($listResult.Content) {
        $parsed = $listResult.Content | ConvertFrom-Json
        if ($parsed.properties) {
            $parsed.properties.PSObject.Properties | ForEach-Object {
                $props[$_.Name] = [string]$_.Value
            }
        }
    }
    foreach ($key in $Settings.Keys) {
        $props[$key] = [string]$Settings[$key]
    }

    $payload = @{ properties = $props } | ConvertTo-Json -Depth 10 -Compress
    $putResult = Invoke-AzRestMethod -Path "$($site.ResourceId)/config/appsettings?api-version=2023-12-01" -Method PUT -Payload $payload -ErrorAction Stop
    if ($putResult.StatusCode -notin 200, 201, 202) {
        throw "Failed to update app settings via ARM (status $($putResult.StatusCode)): $($putResult.Content)"
    }
}

function Get-AzAccessTokenString {
    $tokenObj = Get-AzAccessToken -ErrorAction Stop
    if ($tokenObj.Token -is [SecureString]) {
        return [System.Net.NetworkCredential]::new('', $tokenObj.Token).Password
    }
    return [string]$tokenObj.Token
}

# Post-deploy verification for Event Hub forwarder (Classic + Flex)
# Retries + multi-api-version listing: Basic plans and Azure Government can be slow / picky about API versions.
function Assert-ForwarderDeployment {
    param(
        [string]$ResourceGroupName,
        [string]$FunctionAppName,
        [string]$ExpectedFunctionName = "EventHubTrigger",
        [string[]]$RequiredSettings = @("EVENTHUB_CONNECTION", "EVENT_HUB_NAME", "AzureWebJobsStorage", "SYSLOG_SERVER"),
        [int]$MaxAttempts = 8,
        [int]$RetryDelaySeconds = 15
    )

    Write-Host "Verifying deployed functions and app settings..."
    $site = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceName $FunctionAppName -ResourceType "Microsoft.Web/sites" -ErrorAction Stop

    # Prefer broadly available versions first (Gov-friendly), then newer.
    $apiVersions = @("2022-03-01", "2023-01-01", "2023-12-01")
    $functionNames = @()
    $lastListDetail = "no list attempts yet"

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Invoke-AzResourceAction -ResourceGroupName $ResourceGroupName `
                -ResourceType "Microsoft.Web/sites" `
                -ResourceName $FunctionAppName `
                -Action "syncfunctiontriggers" `
                -Force -ErrorAction Stop | Out-Null
            Write-Host "Synced function triggers (attempt $attempt/$MaxAttempts)" -ForegroundColor Gray
        }
        catch {
            Write-Host "Warning: syncfunctiontriggers failed (attempt $attempt): $_" -ForegroundColor Yellow
        }

        $functionNames = @()
        foreach ($apiVersion in $apiVersions) {
            try {
                $functionsResult = Invoke-AzRestMethod -Path "$($site.ResourceId)/functions?api-version=$apiVersion" -Method GET -ErrorAction Stop
                $statusCode = [int]$functionsResult.StatusCode
                $lastListDetail = "api-version=$apiVersion status=$statusCode"

                if ($statusCode -lt 200 -or $statusCode -ge 300) {
                    Write-Host "Functions list returned $statusCode for api-version $apiVersion" -ForegroundColor Yellow
                    if ($functionsResult.Content) {
                        Write-Host "  Body: $($functionsResult.Content.Substring(0, [Math]::Min(300, $functionsResult.Content.Length)))" -ForegroundColor Yellow
                    }
                    continue
                }

                if ($functionsResult.Content) {
                    $functionsJson = $functionsResult.Content | ConvertFrom-Json
                    if ($functionsJson.value) {
                        $functionNames = @($functionsJson.value | ForEach-Object {
                            if ($_.name -match '/') { ($_.name -split '/')[-1] } else { $_.name }
                        })
                    }
                    elseif ($functionsJson.name) {
                        # Some responses return a single function object
                        $n = $functionsJson.name
                        $functionNames = @($(if ($n -match '/') { ($n -split '/')[-1] } else { $n }))
                    }
                }

                Write-Host "Functions list ($lastListDetail): found $($functionNames.Count) function(s)" -ForegroundColor Gray
                if ($functionNames.Count -gt 0) { break }
            }
            catch {
                $lastListDetail = "api-version=$apiVersion error=$_"
                Write-Host "Functions list failed ($lastListDetail)" -ForegroundColor Yellow
            }
        }

        if ($functionNames.Count -gt 0 -and ($functionNames | Where-Object { $_ -eq $ExpectedFunctionName -or $_ -like "*$ExpectedFunctionName" })) {
            break
        }

        if ($attempt -lt $MaxAttempts) {
            Write-Host "Function '$ExpectedFunctionName' not registered yet (attempt $attempt/$MaxAttempts; $lastListDetail). Waiting ${RetryDelaySeconds}s..." -ForegroundColor Yellow
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }

    if ($functionNames.Count -eq 0) {
        throw "No functions registered after deploy (after $MaxAttempts attempts). Expected '$ExpectedFunctionName'. Last list result: $lastListDetail. Check Kudu wwwroot/EventHubTrigger, host logs, and that the App Service Plan is Windows for Classic."
    }

    Write-Host "Registered functions: $($functionNames -join ', ')" -ForegroundColor Green
    if (-not ($functionNames | Where-Object { $_ -eq $ExpectedFunctionName -or $_ -like "*$ExpectedFunctionName" })) {
        throw "Function '$ExpectedFunctionName' was not found among registered functions: $($functionNames -join ', ')"
    }

    $settingsOk = $false
    $settingsError = $null
    foreach ($apiVersion in $apiVersions) {
        try {
            $settingsCheck = Invoke-AzRestMethod -Path "$($site.ResourceId)/config/appsettings/list?api-version=$apiVersion" -Method POST -ErrorAction Stop
            if ([int]$settingsCheck.StatusCode -ge 200 -and [int]$settingsCheck.StatusCode -lt 300) {
                $settingsProps = ($settingsCheck.Content | ConvertFrom-Json).properties
                foreach ($required in $RequiredSettings) {
                    if (-not $settingsProps.$required) {
                        throw "Required app setting '$required' is missing after deploy."
                    }
                    Write-Host "App setting present: $required" -ForegroundColor Green
                }
                $settingsOk = $true
                break
            }
            $settingsError = "api-version=$apiVersion status=$($settingsCheck.StatusCode)"
        }
        catch {
            $settingsError = "api-version=$apiVersion error=$_"
        }
    }
    if (-not $settingsOk) {
        throw "Could not verify required app settings after deploy. Last error: $settingsError"
    }
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

# Resolve Auto after authentication so an existing named plan can determine the hosting mode.
$autoResolution = $null
if ($HostingPlan -eq "Auto") {
    $existingNamedPlan = $null
    if ($AppServicePlanName) {
        $existingNamedPlan = @(
            Get-AzAppServicePlan `
                -ResourceGroupName $AppServicePlanResourceGroup `
                -ErrorAction Stop |
                Where-Object { $_.Name -eq $AppServicePlanName }
        ) | Select-Object -First 1
    }

    if ($existingNamedPlan) {
        $HostingPlan = if ($existingNamedPlan.Sku.Tier -eq "FlexConsumption") { "FlexConsumption" } else { "Classic" }
        $autoResolution = "Auto inferred from existing plan SKU '$($existingNamedPlan.Sku.Name)/$($existingNamedPlan.Sku.Tier)'"
    }
    else {
        $HostingPlan = if ($AzureCloud -eq "AzureUSGovernment") { "Classic" } else { "FlexConsumption" }
        $autoResolution = if ($AzureCloud -eq "AzureUSGovernment") { "Auto default for Azure Government" } else { "Auto default for Azure Public" }
    }
}

$isFlexConsumption = ($HostingPlan -eq "FlexConsumption")
if ($isFlexConsumption -and $AzureCloud -eq "AzureUSGovernment") {
    throw "Flex Consumption is not currently available in Azure Government. Use -HostingPlan Classic with -AzureCloud AzureUSGovernment."
}

if ($isFlexConsumption) {
    $resolutionNote = if ($autoResolution) { " ($autoResolution)" } else { "" }
    Write-Host "Hosting plan: Flex Consumption (Linux, PowerShell 7.4)$resolutionNote" -ForegroundColor Cyan
    if (-not $AppServicePlanName) {
        $AppServicePlanName = "$FunctionAppName-plan"
        $AppServicePlanResourceGroup = $ResourceGroupName
    }
}
else {
    $resolutionNote = if ($autoResolution) { " ($autoResolution)" } else { "" }
    Write-Host "Hosting plan: Classic (Windows plan / existing ASP)$resolutionNote"
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

# Create or verify hosting plan
if ($isFlexConsumption) {
    # Flex: create FC1 Linux plan with the app (one app per Flex plan). Not a shared classic ASP.
    Write-Host "Creating or verifying Flex Consumption plan: $AppServicePlanName"
    $appServicePlan = Get-AzAppServicePlan -ResourceGroupName $AppServicePlanResourceGroup -Name $AppServicePlanName -ErrorAction SilentlyContinue

    if ($appServicePlan -and $appServicePlan.Sku.Tier -ne "FlexConsumption") {
        throw "App Service Plan '$AppServicePlanName' exists but is SKU '$($appServicePlan.Sku.Tier)', not FlexConsumption. Use a new plan name or HostingPlan Classic."
    }

    if (-not $appServicePlan) {
        Write-Host "Creating Flex Consumption plan (FC1, Linux) via ARM..."
        $appServicePlan = New-FlexConsumptionPlanWithRetry `
            -ResourceGroupName $AppServicePlanResourceGroup `
            -Name $AppServicePlanName `
            -Location $Location
        Write-Host "Created Flex Consumption plan: $AppServicePlanName" -ForegroundColor Green
    }
    else {
        Write-Host "Using existing Flex Consumption plan: $AppServicePlanName"
    }
}
elseif (-not $AppServicePlanName) {
    # Generate default plan name from function app name
    $AppServicePlanName = "$FunctionAppName-plan"
    $AppServicePlanResourceGroup = $ResourceGroupName
    $useBasicPlan = ($AzureCloud -eq "AzureUSGovernment")
    $defaultPlanDescription = if ($useBasicPlan) { "Basic (B1)" } else { "Consumption (Y1)" }
    
    Write-Host "No App Service Plan specified. Creating default $defaultPlanDescription plan: $AppServicePlanName"
    
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
            Write-Host "Deleting and recreating with $defaultPlanDescription plan..." -ForegroundColor Yellow
            Remove-AzAppServicePlan -ResourceGroupName $AppServicePlanResourceGroup -Name $AppServicePlanName -Force
            $needsCreation = $true
        } elseif ($existingSku -eq "FlexConsumption") {
            throw "App Service Plan '$AppServicePlanName' is Flex Consumption, but -HostingPlan is Classic. Use a different plan name for Classic, or pass -HostingPlan FlexConsumption."
        } else {
            Write-Host "Using existing plan: $AppServicePlanName (SKU: $existingSku)"
        }
    }
    
    if ($needsCreation) {
        Write-Host "Creating $defaultPlanDescription plan via ARM API..."
        
        $planProperties = @{
            reserved = $false  # Windows plan (set to $true for Linux)
        }
        
        $planSku = if ($useBasicPlan) {
            @{
                name = "B1"
                tier = "Basic"
                size = "B1"
                family = "B"
                capacity = 1
            }
        } else {
            @{
                name = "Y1"
                tier = "Dynamic"
            }
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
        
        Write-Host "Created $defaultPlanDescription plan: $AppServicePlanName" -ForegroundColor Green
    }
} else {
    # Verify the explicitly provided App Service Plan exists
    Write-Host "Verifying App Service Plan: $AppServicePlanName"
    
    $appServicePlan = Get-AzAppServicePlan -ResourceGroupName $AppServicePlanResourceGroup -Name $AppServicePlanName -ErrorAction SilentlyContinue
    
    if (-not $appServicePlan) {
        throw "App Service Plan '$AppServicePlanName' not found in resource group '$AppServicePlanResourceGroup'. Please create the App Service Plan first or specify an existing plan."
    }

    if ($appServicePlan.Sku.Tier -eq "FlexConsumption") {
        throw "App Service Plan '$AppServicePlanName' is Flex Consumption, but -HostingPlan is Classic. Pass -HostingPlan FlexConsumption, or choose a Classic plan."
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
    $existingPlanId = $existingApp.ServerFarmId
    $existingTier = $null
    if ($existingPlanId) {
        $existingPlanResource = Get-AzResource -ResourceId $existingPlanId -ErrorAction SilentlyContinue
        if ($existingPlanResource -and $existingPlanResource.Sku) {
            $existingTier = $existingPlanResource.Sku.Tier
        }
    }

    if (-not $isFlexConsumption -and $existingTier -eq "FlexConsumption") {
        throw "Function App '$FunctionAppName' is on a Flex Consumption plan, but -HostingPlan is Classic. Use -HostingPlan FlexConsumption, or create a new Function App name for Classic."
    }
    if ($isFlexConsumption -and $existingTier -and $existingTier -ne "FlexConsumption") {
        throw "Function App '$FunctionAppName' already exists on a non-Flex plan ($existingTier). Azure does not support in-place migration to Flex Consumption. Create a new Function App name with -HostingPlan FlexConsumption."
    }

    if ($isFlexConsumption) {
        Write-Host "Existing Flex Function App - skipping Update-AzFunctionApp (unsupported on Flex)"
    }
    else {
        $functionApp = Update-AzFunctionApp `
            -ResourceGroupName $ResourceGroupName `
            -Name $FunctionAppName
    }
} else {
    Write-Host "Creating new Function App..."
    Write-Host "  Name: $FunctionAppName"
    Write-Host "  Plan: $AppServicePlanName"
    Write-Host "  Storage: $StorageAccountName"
    Write-Host "  Runtime: PowerShell 7.4"

    $storageConnectionString = "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$((Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName)[0].Value);EndpointSuffix=$storageEndpointSuffix"

    # Flex Consumption: Linux app created with functionAppConfig (not classic worker-runtime app settings)
    if ($isFlexConsumption) {
        Write-Host "Creating Flex Consumption Function App (Linux) via ARM..." -ForegroundColor Yellow

        # Ensure deployment container exists
        try {
            $storageCtx = $storageAccount.Context
            if (-not $storageCtx) {
                $storageCtx = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName).Context
            }
            $deployContainer = Get-AzStorageContainer -Name "deployments" -Context $storageCtx -ErrorAction SilentlyContinue
            if (-not $deployContainer) {
                New-AzStorageContainer -Name "deployments" -Context $storageCtx -Permission Off | Out-Null
                Write-Host "Created deployments blob container" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "Warning: Could not ensure deployments container exists: $_" -ForegroundColor Yellow
        }

        $functionAppProperties = @{
            serverFarmId = $appServicePlan.Id
            reserved     = $true
            httpsOnly    = $true
            siteConfig   = @{
                appSettings = @(
                    @{ name = "AzureWebJobsStorage"; value = $storageConnectionString }
                    @{ name = "APPLICATIONINSIGHTS_CONNECTION_STRING"; value = $appInsightsConnectionString }
                    @{ name = "APPINSIGHTS_INSTRUMENTATIONKEY"; value = $appInsightsInstrumentationKey }
                    @{ name = "FUNCTIONS_EXTENSION_VERSION"; value = "~4" }
                    @{ name = "SYSLOG_SERVER"; value = $SyslogServer }
                    @{ name = "SYSLOG_PORT"; value = "$SyslogPort" }
                    @{ name = "SYSLOG_PROTOCOL"; value = $Protocol }
                    @{ name = "EVENT_HUB_NAME"; value = $EventHubName }
                    @{ name = "EVENTHUB_CONNECTION"; value = $EventHubConnection }
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
                    instanceMemoryMB     = $FlexInstanceMemoryMB
                }
                runtime = @{
                    name    = "powershell"
                    version = "7.4"
                }
            }
        }

        try {
            $functionApp = New-AzResource `
                -ResourceGroupName $ResourceGroupName `
                -ResourceType "Microsoft.Web/sites" `
                -ResourceName $FunctionAppName `
                -Location $Location `
                -Properties $functionAppProperties `
                -Kind "functionapp,linux" `
                -Force

            Write-Host "Function App created successfully with Flex Consumption plan" -ForegroundColor Green
            Start-Sleep -Seconds 10
            $functionApp = Get-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName
        }
        catch {
            Write-Host "Error creating Flex Consumption Function App: $_" -ForegroundColor Red
            throw
        }
    }
    else {
        # Standard plans (Consumption, Basic, Premium) use Az.Functions module / ARM
        try {
            # Check if this is a Consumption plan (Dynamic tier)
            $isConsumption = $appServicePlan.Sku.Tier -eq "Dynamic"

            if ($isConsumption) {
                Write-Host "Detected Consumption plan (Y1) - using ARM deployment..." -ForegroundColor Yellow

                # Consumption plans have issues with New-AzFunctionApp trying to set AlwaysOn
                # Use ARM API for Windows Consumption
                $functionAppProperties = @{
                    serverFarmId = $appServicePlan.Id
                    siteConfig = @{
                        appSettings = @(
                            @{ name = "AzureWebJobsStorage"; value = $storageConnectionString }
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

# Configure HTTPS, TLS, and HTTP/2 settings using the ARM configuration endpoint
Write-Host "Configuring HTTPS-only, TLS 1.2, and HTTP/2..."
$functionAppProperties = @{
    "httpsOnly" = $true
}
Set-AzResource -ResourceId $functionAppResource.ResourceId -Properties $functionAppProperties -Force | Out-Null

$webConfigPath = "$($functionAppResource.ResourceId)/config/web?api-version=2023-12-01"
$webConfigPayload = @{
    properties = @{
        http20Enabled    = $true
        minTlsVersion    = "1.2"
        scmMinTlsVersion = "1.2"
    }
} | ConvertTo-Json -Depth 5 -Compress

$webConfigResult = Invoke-AzRestMethod -Path $webConfigPath -Method PATCH -Payload $webConfigPayload -ErrorAction Stop
if ($webConfigResult.StatusCode -notin 200, 201, 202) {
    throw "Failed to configure Function App web settings. ARM returned status $($webConfigResult.StatusCode): $($webConfigResult.Content)"
}

$webConfigResult = Invoke-AzRestMethod -Path $webConfigPath -Method GET -ErrorAction Stop
$webConfig = $webConfigResult.Content | ConvertFrom-Json
if ($webConfig.properties.http20Enabled -ne $true) {
    throw "HTTP/2 verification failed for Function App '$FunctionAppName'."
}
Write-Host "HTTPS-only, TLS 1.2, and HTTP/2 configured successfully" -ForegroundColor Green

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
# Update-AzFunctionApp does not support Flex Consumption — use ARM/REST for Flex.
Write-Host "Enabling system-assigned managed identity..."
try {
    $principalId = $null

    if ($isFlexConsumption) {
        Write-Host "Flex Consumption detected - enabling identity via ARM REST..."
        $siteResource = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceName $FunctionAppName -ResourceType "Microsoft.Web/sites" -ErrorAction Stop

        # Update-AzFunctionApp / New-AzResource -IdentityType are unsupported on Flex or older Az modules.
        # PATCH identity via ARM REST (works across module versions).
        $payload = @{ identity = @{ type = "SystemAssigned" } } | ConvertTo-Json -Compress
        $restResult = Invoke-AzRestMethod -Path "$($siteResource.ResourceId)?api-version=2023-12-01" -Method PATCH -Payload $payload -ErrorAction Stop
        if ($restResult.StatusCode -notin 200, 201, 202) {
            throw "ARM identity PATCH failed with status $($restResult.StatusCode): $($restResult.Content)"
        }

        # Re-read identity principal id
        Start-Sleep -Seconds 5
        $siteResource = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceName $FunctionAppName -ResourceType "Microsoft.Web/sites" -ExpandProperties -ErrorAction SilentlyContinue
        if ($siteResource.Identity -and $siteResource.Identity.PrincipalId) {
            $principalId = $siteResource.Identity.PrincipalId
        }
        elseif ($siteResource.Properties.identity -and $siteResource.Properties.identity.principalId) {
            $principalId = $siteResource.Properties.identity.principalId
        }
        else {
            # Parse from REST GET as fallback
            $getResult = Invoke-AzRestMethod -Path "$($siteResource.ResourceId)?api-version=2023-12-01" -Method GET -ErrorAction SilentlyContinue
            if ($getResult -and $getResult.Content) {
                $siteJson = $getResult.Content | ConvertFrom-Json
                if ($siteJson.identity -and $siteJson.identity.principalId) {
                    $principalId = $siteJson.identity.principalId
                }
            }
        }
    }
    else {
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
        if ($identityApp) {
            if ($identityApp.PSObject.Properties["IdentityPrincipalId"]) {
                $principalId = $identityApp.IdentityPrincipalId
            }
            elseif ($identityApp.Identity -and $identityApp.Identity.PrincipalId) {
                $principalId = $identityApp.Identity.PrincipalId
            }
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

# Configure runtime versions with retry logic (Classic only — Flex uses functionAppConfig + ARM settings)
Write-Host "Configuring runtime versions..."
if (-not $isFlexConsumption) {
    $runtimeSettings = @{
        "FUNCTIONS_WORKER_RUNTIME"         = "powershell"
        "FUNCTIONS_WORKER_RUNTIME_VERSION" = "7.4"
        "FUNCTIONS_EXTENSION_VERSION"      = "~4"
        "WEBSITE_RUN_FROM_PACKAGE"         = "0"  # Enable in-portal editing
        "WEBSITE_HTTPSONLY"               = "1"  # Force HTTPS
    }

    $retryCount = 0
    $maxRetries = 5
    while ($retryCount -lt $maxRetries) {
        try {
            Update-AzFunctionAppSetting -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -AppSetting $runtimeSettings -Confirm:$false -ErrorAction Stop
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
}
else {
    Write-Host "Flex Consumption - runtime configured via functionAppConfig; skipping Classic runtime app settings" -ForegroundColor Yellow
    Start-Sleep -Seconds 10
}

# Configure environment variables
Write-Host "Configuring environment variables..."
$storageConnectionString = "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$((Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName)[0].Value);EndpointSuffix=$storageEndpointSuffix"
$settings = @{
    "AzureWebJobsStorage"                      = $storageConnectionString
    "SYSLOG_SERVER"                            = $SyslogServer
    "SYSLOG_PORT"                              = "$SyslogPort"
    "SYSLOG_PROTOCOL"                          = $Protocol
    "EVENT_HUB_NAME"                           = $EventHubName
    "EVENTHUB_CONNECTION"                      = $EventHubConnection
    "APPLICATIONINSIGHTS_CONNECTION_STRING"    = $appInsightsConnectionString
    "APPINSIGHTS_INSTRUMENTATIONKEY"           = $appInsightsInstrumentationKey
    "FUNCTIONS_EXTENSION_VERSION"              = "~4"
}
if (-not $isFlexConsumption) {
    $settings["WEBSITE_RUN_FROM_PACKAGE"] = "0"
    $settings["FUNCTIONS_WORKER_RUNTIME"] = "powershell"
    $settings["FUNCTIONS_WORKER_RUNTIME_VERSION"] = "7.4"
}

if ($isFlexConsumption) {
    Write-Host "Applying app settings via ARM (Flex-safe)..."
    Set-FunctionAppSettingsViaArm -ResourceGroupName $ResourceGroupName -FunctionAppName $FunctionAppName -Settings $settings
    Write-Host "App settings applied via ARM" -ForegroundColor Green
}
else {
    Update-AzFunctionAppSetting -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -AppSetting $settings -Confirm:$false
}

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

    if ($isFlexConsumption) {
        # Flex only supports OneDeploy (not Publish-AzWebApp / classic zipdeploy)
        Write-Host "Flex Consumption - using OneDeploy (/api/publish?type=zip)..." -ForegroundColor Yellow

        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "funcapp-$(Get-Random)"
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

        $funcDir = Join-Path $tempDir "EventHubTrigger"
        New-Item -ItemType Directory -Path $funcDir -Force | Out-Null

        Copy-Item -Path (Join-Path $srcPath "function.json") -Destination $funcDir
        Copy-Item -Path (Join-Path $srcPath "run.ps1") -Destination $funcDir
        Copy-Item -Path (Join-Path $srcPath "host.json") -Destination $tempDir

        $zipPath = Join-Path ([System.IO.Path]::GetTempPath()) "funcapp-$(Get-Random).zip"
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

        Write-Host "Creating deployment package: $zipPath"
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($tempDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

        # Resolve SCM host (supports public + sovereign clouds)
        try {
            $functionAppDetails = Get-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -ErrorAction Stop
            $defaultHost = $functionAppDetails.DefaultHostName
        }
        catch {
            $defaultHost = $null
        }

        if ($defaultHost) {
            $kuduHost = ($defaultHost -replace '(^[^\.]+)\.', '$1.scm.')
        }
        else {
            $kuduHost = "$FunctionAppName.scm.azurewebsites.net"
        }

        $siteResource = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceName $FunctionAppName -ResourceType "Microsoft.Web/sites" -ErrorAction Stop

        # Enable SCM basic auth (often disabled on new apps; needed for some deploy paths)
        try {
            $scmPolicyPayload = @{ properties = @{ allow = $true } } | ConvertTo-Json -Compress
            Invoke-AzRestMethod -Path "$($siteResource.ResourceId)/basicPublishingCredentialsPolicies/scm?api-version=2023-12-01" `
                -Method PUT -Payload $scmPolicyPayload -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            Write-Host "Warning: Could not enable SCM basic auth policy: $_" -ForegroundColor Yellow
        }

        $publishUrl = "https://$kuduHost/api/publish?type=zip&remoteBuild=false"
        Write-Host "Deploying package via OneDeploy: $publishUrl"

        $deployed = $false

        # Prefer Azure CLI when available (handles Flex OneDeploy reliably)
        if (Get-Command az -ErrorAction SilentlyContinue) {
            try {
                Write-Host "Attempting Azure CLI config-zip deploy..."
                az functionapp deployment source config-zip `
                    --resource-group $ResourceGroupName `
                    --name $FunctionAppName `
                    --src $zipPath `
                    --only-show-errors
                if ($LASTEXITCODE -eq 0) {
                    $deployed = $true
                    Write-Host "Function code deployed successfully via Azure CLI" -ForegroundColor Green
                }
                else {
                    Write-Host "Azure CLI deploy exited with code $LASTEXITCODE, trying SCM OneDeploy..." -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "Azure CLI deploy failed, falling back to SCM OneDeploy: $_" -ForegroundColor Yellow
            }
        }

        if (-not $deployed) {
            # Prefer AAD bearer token (works when basic auth is disabled)
            try {
                $accessToken = Get-AzAccessTokenString
                Write-Host "Attempting SCM OneDeploy with AAD token..."
                Invoke-RestMethod -Uri $publishUrl `
                    -Method POST `
                    -Headers @{ Authorization = "Bearer $accessToken" } `
                    -InFile $zipPath `
                    -ContentType "application/octet-stream" `
                    -ErrorAction Stop | Out-Null
                $deployed = $true
                Write-Host "Function code deployed successfully via SCM OneDeploy (AAD)" -ForegroundColor Green
            }
            catch {
                Write-Host "AAD OneDeploy failed, trying basic auth: $_" -ForegroundColor Yellow
                $publishingCredentials = Invoke-AzResourceAction -ResourceGroupName $ResourceGroupName `
                    -ResourceType Microsoft.Web/sites/config `
                    -ResourceName "$FunctionAppName/publishingcredentials" `
                    -Action list -Force
                $username = $publishingCredentials.Properties.PublishingUserName
                $password = $publishingCredentials.Properties.PublishingPassword
                $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${username}:${password}"))

                Invoke-RestMethod -Uri $publishUrl `
                    -Method POST `
                    -Headers @{ Authorization = "Basic $base64Auth" } `
                    -InFile $zipPath `
                    -ContentType "application/octet-stream" `
                    -ErrorAction Stop | Out-Null
                $deployed = $true
                Write-Host "Function code deployed successfully via SCM OneDeploy (basic auth)" -ForegroundColor Green
            }
        }

        if (-not $deployed) {
            throw "Flex OneDeploy failed with all methods."
        }

        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue

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

    # Basic/dedicated plans (and Gov) often need longer before /functions is populated
    Write-Host "Waiting 30 seconds for function host to index after restart..."
    Start-Sleep -Seconds 30
    Assert-ForwarderDeployment -ResourceGroupName $ResourceGroupName -FunctionAppName $FunctionAppName
}
catch {
    Write-Host "Failed to deploy function code: $_" -ForegroundColor Red
    throw
}

Write-Host "`nDeployment completed!"
Write-Host "`nFunction App Details:"
Write-Host "Name: $FunctionAppName"
Write-Host "Hosting: $(if ($isFlexConsumption) { 'Flex Consumption (Linux)' } else { 'Classic' })"
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
Write-Host "- System-assigned managed identity: Enabled (attempted)" 
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
    [string]$AppServicePlanResourceGroup,

    # Optional existing (already secured) storage account. Requires -VNetName and -IntegrationSubnetName.
    [Parameter(Mandatory = $false)]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $false)]
    [string]$StorageAccountResourceGroup,

    # Secure storage networking. VNet/subnets are customer prerequisites.
    [Parameter(Mandatory = $false)]
    [string]$VNetName,

    [Parameter(Mandatory = $false)]
    [string]$VNetResourceGroup,

    [Parameter(Mandatory = $false)]
    [string]$IntegrationSubnetName,

    [Parameter(Mandatory = $false)]
    [string]$PrivateEndpointSubnetName
)

# Error handling
$ErrorActionPreference = 'Stop'

$script:SecureStorageManagedByTag = "AzureNetworkFirewallSupport"
$script:SecureStorageGroupIds = @("blob", "file", "queue", "table")

function Get-ResourceManagedByTag {
    param($Resource)

    if (-not $Resource) {
        return $null
    }

    if ($Resource.Tags -and $Resource.Tags.ContainsKey("ManagedBy")) {
        return [string]$Resource.Tags["ManagedBy"]
    }
    if ($Resource.Tag -and $Resource.Tag.ContainsKey("ManagedBy")) {
        return [string]$Resource.Tag["ManagedBy"]
    }

    return $null
}

function Test-IsDeployOwnedResource {
    param($Resource)

    return (Get-ResourceManagedByTag -Resource $Resource) -eq $script:SecureStorageManagedByTag
}

function Resolve-SecureStorageMode {
    param(
        [string]$StorageAccountName,
        [string]$VNetName,
        [string]$IntegrationSubnetName,
        [string]$PrivateEndpointSubnetName
    )

    $hasStorage = -not [string]::IsNullOrWhiteSpace($StorageAccountName)
    $hasVNet = -not [string]::IsNullOrWhiteSpace($VNetName)
    $hasIntegration = -not [string]::IsNullOrWhiteSpace($IntegrationSubnetName)
    $hasPe = -not [string]::IsNullOrWhiteSpace($PrivateEndpointSubnetName)

    if ($hasStorage) {
        if (-not $hasVNet -or -not $hasIntegration) {
            throw "When -StorageAccountName is specified, -VNetName and -IntegrationSubnetName are required so the Function App can reach that storage account."
        }
        if ($hasPe) {
            Write-Host "Note: -PrivateEndpointSubnetName is ignored when using an existing storage account." -ForegroundColor Yellow
        }
        return "Existing"
    }

    if ($hasVNet -or $hasIntegration -or $hasPe) {
        if (-not $hasVNet -or -not $hasIntegration -or -not $hasPe) {
            throw "Create-and-lock secure storage requires -VNetName, -IntegrationSubnetName, and -PrivateEndpointSubnetName. To use an existing locked storage account, pass -StorageAccountName instead."
        }
        return "CreateAndLock"
    }

    return "Public"
}

function Assert-SecureStorageModules {
    foreach ($moduleName in @("Az.Network", "Az.PrivateDns", "Az.Storage")) {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            throw "Secure storage requires the $moduleName PowerShell module. Install it with: Install-Module $moduleName"
        }
        Import-Module $moduleName -ErrorAction Stop
    }
}

function Assert-SecureStorageHostingPlan {
    param(
        [object]$AppServicePlan,
        [bool]$IsFlexConsumption
    )

    if ($IsFlexConsumption) {
        return
    }

    $tier = $null
    if ($AppServicePlan -and $AppServicePlan.Sku) {
        $tier = $AppServicePlan.Sku.Tier
    }

    if ($tier -eq "Dynamic") {
        throw "Secure storage requires regional VNet integration, which Consumption (Y1) does not support. Pass -AppServicePlanName for a Basic or Premium plan, or use -HostingPlan FlexConsumption."
    }
}

function Get-RequiredIntegrationDelegation {
    param([bool]$IsFlexConsumption)

    if ($IsFlexConsumption) {
        return "Microsoft.App/environments"
    }

    return "Microsoft.Web/serverFarms"
}

function Assert-FlexAppResourceProvider {
    param(
        [int]$TimeoutSeconds = 300,
        [int]$PollIntervalSeconds = 15
    )

    $provider = Get-AzResourceProvider -ProviderNamespace "Microsoft.App" -ErrorAction SilentlyContinue
    $state = $null
    if ($provider) {
        $state = @($provider)[0].RegistrationState
    }

    if ($state -eq "Registered") {
        Write-Host "Resource provider Microsoft.App is registered"
        return
    }

    Write-Host "Registering resource provider Microsoft.App (required for Flex VNet integration)..."
    try {
        Register-AzResourceProvider -ProviderNamespace "Microsoft.App" -ErrorAction Stop | Out-Null
    }
    catch {
        throw "Flex VNet integration requires the Microsoft.App resource provider. Register it with a subscription Owner or Contributor, then rerun deploy: Register-AzResourceProvider -ProviderNamespace Microsoft.App. Original error: $_"
    }

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $provider = Get-AzResourceProvider -ProviderNamespace "Microsoft.App" -ErrorAction SilentlyContinue
        $state = if ($provider) { @($provider)[0].RegistrationState } else { $null }
        if ($state -eq "Registered") {
            Write-Host "Resource provider Microsoft.App is registered" -ForegroundColor Green
            return
        }

        Write-Host "Waiting for Microsoft.App registration... ($elapsed seconds, state=$state)"
        Start-Sleep -Seconds $PollIntervalSeconds
        $elapsed += $PollIntervalSeconds
    }

    throw "Timed out waiting for Microsoft.App to register. Check Get-AzResourceProvider -ProviderNamespace Microsoft.App, then rerun deploy."
}

function Get-VirtualNetworkSubnet {
    param(
        [string]$VNetResourceGroup,
        [string]$VNetName,
        [string]$SubnetName
    )

    $vnet = Get-AzVirtualNetwork -ResourceGroupName $VNetResourceGroup -Name $VNetName -ErrorAction SilentlyContinue
    if (-not $vnet) {
        throw "Virtual network '$VNetName' was not found in resource group '$VNetResourceGroup'."
    }

    $subnet = $vnet.Subnets | Where-Object { $_.Name -eq $SubnetName } | Select-Object -First 1
    if (-not $subnet) {
        throw "Subnet '$SubnetName' was not found on virtual network '$VNetName'."
    }

    return @{
        VirtualNetwork = $vnet
        Subnet         = $subnet
    }
}

function Test-SecureStorageNetworkingPrereqs {
    param(
        [string]$VNetResourceGroup,
        [string]$VNetName,
        [string]$IntegrationSubnetName,
        [string]$PrivateEndpointSubnetName,
        [bool]$IsFlexConsumption,
        [bool]$RequirePrivateEndpointSubnet
    )

    if ($IsFlexConsumption) {
        Assert-FlexAppResourceProvider
    }

    $integration = Get-VirtualNetworkSubnet -VNetResourceGroup $VNetResourceGroup -VNetName $VNetName -SubnetName $IntegrationSubnetName
    $requiredDelegation = Get-RequiredIntegrationDelegation -IsFlexConsumption $IsFlexConsumption
    $delegations = @($integration.Subnet.Delegations | ForEach-Object { $_.ServiceName })
    if ($delegations -notcontains $requiredDelegation) {
        throw "Integration subnet '$IntegrationSubnetName' must be delegated to '$requiredDelegation' for this hosting mode. Current delegations: $(if ($delegations) { $delegations -join ', ' } else { 'none' })."
    }

    $peSubnet = $null
    if ($RequirePrivateEndpointSubnet) {
        if ($PrivateEndpointSubnetName -eq $IntegrationSubnetName) {
            throw "Private endpoint subnet must be different from the Function App integration subnet."
        }

        $pe = Get-VirtualNetworkSubnet -VNetResourceGroup $VNetResourceGroup -VNetName $VNetName -SubnetName $PrivateEndpointSubnetName
        $peSubnet = $pe.Subnet
    }

    return @{
        VirtualNetwork           = $integration.VirtualNetwork
        IntegrationSubnet        = $integration.Subnet
        PrivateEndpointSubnet    = $peSubnet
        IntegrationSubnetId      = $integration.Subnet.Id
        PrivateEndpointSubnetObj = $peSubnet
    }
}

function Get-StorageAccountConnectionString {
    param(
        [string]$ResourceGroupName,
        [string]$StorageAccountName,
        [string]$EndpointSuffix
    )

    $key = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop)[0].Value
    return "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$key;EndpointSuffix=$EndpointSuffix"
}

function Set-DeployOwnedResourceTag {
    param(
        [string]$ResourceId
    )

    $tags = @{ ManagedBy = $script:SecureStorageManagedByTag }
    try {
        Update-AzTag -ResourceId $ResourceId -Tag $tags -Operation Merge -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Host "Warning: Could not tag resource '$ResourceId': $_" -ForegroundColor Yellow
    }
}

function New-OrGetFunctionStorageAccount {
    param(
        [string]$ResourceGroupName,
        [string]$StorageAccountName,
        [string]$Location,
        [string]$Mode
    )

    $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
    if ($storageAccount) {
        Write-Host "Using existing storage account: $StorageAccountName" -ForegroundColor Green
        if ($Mode -eq "CreateAndLock" -and -not (Test-IsDeployOwnedResource -Resource $storageAccount)) {
            Set-DeployOwnedResourceTag -ResourceId $storageAccount.Id
        }
        return $storageAccount
    }

    if ($Mode -eq "Existing") {
        throw "Storage account '$StorageAccountName' was not found in resource group '$ResourceGroupName'."
    }

    $createParams = @{
        ResourceGroupName      = $ResourceGroupName
        Name                   = $StorageAccountName
        Location               = $Location
        SkuName                = "Standard_LRS"
        MinimumTlsVersion      = "TLS1_2"
        EnableHttpsTrafficOnly = $true
        ErrorAction            = "Stop"
    }
    if ($Mode -ne "Existing") {
        $createParams["Tag"] = @{ ManagedBy = $script:SecureStorageManagedByTag }
    }

    Write-Host "Creating storage account: $StorageAccountName"
    return New-AzStorageAccount @createParams
}

function Get-PrivateLinkDnsZoneName {
    param(
        [string]$GroupId,
        [string]$StorageEndpointSuffix
    )

    return "privatelink.$GroupId.$StorageEndpointSuffix"
}

function Test-IsAzHttpTimeout {
    param([string]$Message)

    return $Message -match '(?i)(HttpClient\.Timeout|A task was canceled|task was canceled|The request was canceled)'
}

function Test-IsTransientAzAuthFailure {
    param([string]$Message)

    return $Message -match '(?i)(ManagedIdentityCredential authentication failed|token provider result value is invalid)'
}

# ConvertTo-Json unwraps a one-item array into an object. A List stays a JSON array at length 0, 1, or many.
function New-ArmJsonArray {
    param([object[]]$Items)

    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($item in @($Items)) {
        if ($null -ne $item) {
            $list.Add($item)
        }
    }
    return ,$list
}

function ConvertTo-ArmJson {
    param($InputObject)

    # ConvertTo-Json turns a one-item array into an object. Newtonsoft keeps arrays as arrays.
    try {
        return [Newtonsoft.Json.JsonConvert]::SerializeObject($InputObject)
    }
    catch {
        return ($InputObject | ConvertTo-Json -Depth 10 -Compress)
    }
}

function Wait-PrivateEndpointReady {
    param(
        [string]$ResourceGroupName,
        [string]$Name,
        [int]$TimeoutSeconds = 300,
        [int]$PollIntervalSeconds = 15
    )

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        try {
            $privateEndpoint = Get-AzPrivateEndpoint -Name $Name -ResourceGroupName $ResourceGroupName -ErrorAction Stop
            $state = [string]$privateEndpoint.ProvisioningState
            if ($state -eq "Failed") {
                throw "Private endpoint '$Name' entered provisioning state Failed."
            }
            if ($privateEndpoint -and ($state -eq "Succeeded" -or [string]::IsNullOrWhiteSpace($state))) {
                return $privateEndpoint
            }
            Write-Host "Waiting for private endpoint $Name... ($elapsed seconds, state=$state)"
        }
        catch {
            $message = "$_"
            if ($message -match "entered provisioning state Failed") {
                throw
            }
            if ($message -match '(?i)(was not found|ResourceNotFound|could not be found|does not exist)') {
                Write-Host "Waiting for private endpoint $Name to appear... ($elapsed seconds)"
            }
            elseif (Test-IsAzHttpTimeout -Message $message) {
                Write-Host "Private endpoint lookup for $Name exceeded the Azure PowerShell HTTP timeout. Retrying..."
            }
            elseif (Test-IsTransientAzAuthFailure -Message $message) {
                Write-Host "Azure rejected the managed identity token while checking private endpoint $Name. Retrying..."
            }
            else {
                throw
            }
        }

        Start-Sleep -Seconds $PollIntervalSeconds
        $elapsed += $PollIntervalSeconds
    }

    throw "Timed out waiting for private endpoint '$Name' to finish provisioning."
}

function New-StoragePrivateEndpointReady {
    param(
        [string]$Name,
        [string]$ResourceGroupName,
        [string]$Location,
        [object]$Subnet,
        [object]$PrivateLinkServiceConnection
    )

    Write-Host "Creating private endpoint $Name"
    $privateEndpoint = $null
    $maxAttempts = 4
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $privateEndpoint = New-AzPrivateEndpoint `
                -Name $Name `
                -ResourceGroupName $ResourceGroupName `
                -Location $Location `
                -Subnet $Subnet `
                -PrivateLinkServiceConnection $PrivateLinkServiceConnection `
                -Tag @{ ManagedBy = $script:SecureStorageManagedByTag } `
                -ErrorAction Stop
            break
        }
        catch {
            $message = "$_"
            if (Test-IsTransientAzAuthFailure -Message $message) {
                if ($attempt -ge $maxAttempts) {
                    throw
                }
                $delay = 10 * $attempt
                Write-Host "Azure rejected the managed identity token while creating private endpoint $Name (attempt $attempt of $maxAttempts). Retrying in $delay seconds..."
                Start-Sleep -Seconds $delay
                continue
            }
            if (-not (Test-IsAzHttpTimeout -Message $message) -and $message -notmatch '(?i)(already exists|Conflict)') {
                throw
            }
            Write-Host "Private endpoint create for $Name exceeded the Azure PowerShell HTTP timeout. Waiting for Azure to finish..."
            break
        }
    }

    $state = [string]$privateEndpoint.ProvisioningState
    if (-not $privateEndpoint -or ($state -and $state -ne "Succeeded")) {
        $privateEndpoint = Wait-PrivateEndpointReady -ResourceGroupName $ResourceGroupName -Name $Name
    }

    return $privateEndpoint
}

function Wait-PrivateDnsZoneGroup {
    param(
        [string]$PrivateEndpointResourceId,
        [string]$PrivateEndpointName,
        [string]$ZoneGroupName = "dns-zone-group",
        [int]$TimeoutSeconds = 300,
        [int]$PollIntervalSeconds = 15
    )

    $path = "$PrivateEndpointResourceId/privateDnsZoneGroups/${ZoneGroupName}?api-version=2023-11-01"
    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        try {
            $result = Invoke-AzRestMethod -Path $path -Method GET -ErrorAction Stop
            if ($result.StatusCode -in 200, 201) {
                $group = $result.Content | ConvertFrom-Json
                $state = [string]$group.properties.provisioningState
                if ($state -eq "Succeeded") {
                    Write-Host "DNS zone group for $PrivateEndpointName is ready" -ForegroundColor Green
                    return
                }
                if ($state -eq "Failed") {
                    throw "DNS zone group '$ZoneGroupName' for $PrivateEndpointName entered provisioning state Failed."
                }
                Write-Host "Waiting for DNS zone group on $PrivateEndpointName... ($elapsed seconds, state=$state)"
            }
            elseif ($result.StatusCode -eq 404) {
                Write-Host "Waiting for DNS zone group on $PrivateEndpointName to appear... ($elapsed seconds)"
            }
            else {
                Write-Host "DNS zone group query for $PrivateEndpointName returned $($result.StatusCode). Retrying..."
            }
        }
        catch {
            $message = "$_"
            if ($message -match "entered provisioning state Failed") {
                throw
            }
            if (Test-IsAzHttpTimeout -Message $message) {
                Write-Host "DNS zone group query for $PrivateEndpointName exceeded the Azure PowerShell HTTP timeout. Retrying..."
            }
            elseif (Test-IsTransientAzAuthFailure -Message $message) {
                Write-Host "Azure rejected the managed identity token while checking the DNS zone group for $PrivateEndpointName. Retrying..."
            }
            else {
                throw
            }
        }

        Start-Sleep -Seconds $PollIntervalSeconds
        $elapsed += $PollIntervalSeconds
    }

    throw "Timed out waiting for private DNS zone group '$ZoneGroupName' on $PrivateEndpointName."
}

function New-StoragePrivateDnsZoneGroup {
    param(
        [string]$PrivateEndpointResourceId,
        [string]$PrivateEndpointName,
        [string]$GroupId,
        [string]$PrivateDnsZoneId
    )

    Write-Host "Creating DNS zone group for $PrivateEndpointName"
    $path = "$PrivateEndpointResourceId/privateDnsZoneGroups/dns-zone-group?api-version=2023-11-01"
    $payload = @{
        properties = @{
            privateDnsZoneConfigs = New-ArmJsonArray -Items @(
                @{
                    name = $GroupId
                    properties = @{
                        privateDnsZoneId = $PrivateDnsZoneId
                    }
                }
            )
        }
    }
    $payload = ConvertTo-ArmJson $payload

    $maxAttempts = 4
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $result = Invoke-AzRestMethod -Path $path -Method PUT -Payload $payload -ErrorAction Stop
            if ($result.StatusCode -notin 200, 201, 202, 409) {
                $message = "$($result.StatusCode) $($result.Content)"
                if (Test-IsTransientAzAuthFailure -Message $message) {
                    if ($attempt -ge $maxAttempts) {
                        throw "Failed to create DNS zone group for ${PrivateEndpointName}: $message"
                    }
                    $delay = 10 * $attempt
                    Write-Host "Azure rejected the managed identity token while creating the DNS zone group for $PrivateEndpointName (attempt $attempt of $maxAttempts). Retrying in $delay seconds..."
                    Start-Sleep -Seconds $delay
                    continue
                }
                if (-not (Test-IsAzHttpTimeout -Message $message)) {
                    throw "Failed to create DNS zone group for ${PrivateEndpointName}: $message"
                }
                Write-Host "DNS zone group create for $PrivateEndpointName exceeded the Azure PowerShell HTTP timeout. Waiting for Azure to finish..."
            }
            break
        }
        catch {
            $message = "$_"
            if ($message -match '^Failed to create DNS zone group') {
                throw
            }
            if (Test-IsTransientAzAuthFailure -Message $message) {
                if ($attempt -ge $maxAttempts) {
                    throw
                }
                $delay = 10 * $attempt
                Write-Host "Azure rejected the managed identity token while creating the DNS zone group for $PrivateEndpointName (attempt $attempt of $maxAttempts). Retrying in $delay seconds..."
                Start-Sleep -Seconds $delay
                continue
            }
            if (-not (Test-IsAzHttpTimeout -Message $message)) {
                throw
            }
            Write-Host "DNS zone group create for $PrivateEndpointName exceeded the Azure PowerShell HTTP timeout. Waiting for Azure to finish..."
            break
        }
    }

    Wait-PrivateDnsZoneGroup -PrivateEndpointResourceId $PrivateEndpointResourceId -PrivateEndpointName $PrivateEndpointName
}

function Set-StoragePrivateDnsAndEndpoints {
    param(
        [string]$ResourceGroupName,
        [string]$Location,
        [string]$StorageAccountName,
        [string]$StorageAccountResourceGroup,
        [object]$PrivateEndpointSubnet,
        [object]$VirtualNetwork,
        [string]$StorageEndpointSuffix
    )

    $storageAccount = Get-AzStorageAccount -ResourceGroupName $StorageAccountResourceGroup -Name $StorageAccountName -ErrorAction Stop

    foreach ($groupId in $script:SecureStorageGroupIds) {
        $zoneName = Get-PrivateLinkDnsZoneName -GroupId $groupId -StorageEndpointSuffix $StorageEndpointSuffix
        $zone = Get-AzPrivateDnsZone -ResourceGroupName $ResourceGroupName -Name $zoneName -ErrorAction SilentlyContinue
        if (-not $zone) {
            Write-Host "Creating private DNS zone $zoneName"
            $zone = New-AzPrivateDnsZone -ResourceGroupName $ResourceGroupName -Name $zoneName
        }

        $link = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ResourceGroupName -ZoneName $zoneName -Name "vnet-link" -ErrorAction SilentlyContinue
        if (-not $link) {
            Write-Host "Linking $zoneName to $($VirtualNetwork.Name)"
            New-AzPrivateDnsVirtualNetworkLink `
                -ResourceGroupName $ResourceGroupName `
                -ZoneName $zoneName `
                -Name "vnet-link" `
                -VirtualNetworkId $VirtualNetwork.Id | Out-Null
        }

        $peName = "$StorageAccountName-$groupId-pe"
        $privateEndpoint = Get-AzPrivateEndpoint -Name $peName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        if (-not $privateEndpoint) {
            $plsConnection = New-AzPrivateLinkServiceConnection `
                -Name "$groupId-connection" `
                -PrivateLinkServiceId $storageAccount.Id `
                -GroupId $groupId
            $privateEndpoint = New-StoragePrivateEndpointReady `
                -Name $peName `
                -ResourceGroupName $ResourceGroupName `
                -Location $Location `
                -Subnet $PrivateEndpointSubnet `
                -PrivateLinkServiceConnection $plsConnection
        }
        else {
            $endpointState = [string]$privateEndpoint.ProvisioningState
            if ($endpointState -and $endpointState -ne "Succeeded") {
                Write-Host "Waiting for existing private endpoint $peName (state=$endpointState)..."
                $privateEndpoint = Wait-PrivateEndpointReady -ResourceGroupName $ResourceGroupName -Name $peName
            }
            if (-not (Test-IsDeployOwnedResource -Resource $privateEndpoint)) {
                Set-DeployOwnedResourceTag -ResourceId $privateEndpoint.Id
            }
        }

        $zoneId = if ($zone.ResourceId) { [string]$zone.ResourceId } else { [string]$zone.Id }
        $zoneGroupPath = "$($privateEndpoint.Id)/privateDnsZoneGroups/dns-zone-group?api-version=2023-11-01"
        $zoneGroupReady = $false
        try {
            $groupResult = Invoke-AzRestMethod -Path $zoneGroupPath -Method GET -ErrorAction Stop
            if ($groupResult.StatusCode -in 200, 201) {
                $groupBody = $groupResult.Content | ConvertFrom-Json
                if ([string]$groupBody.properties.provisioningState -eq "Succeeded") {
                    $zoneGroupReady = $true
                }
            }
        }
        catch {
            $message = "$_"
            if (Test-IsTransientAzAuthFailure -Message $message) {
                Write-Host "Azure rejected the managed identity token while checking the DNS zone group for $peName. Retrying the create..."
            }
            elseif (-not (Test-IsAzHttpTimeout -Message $message)) {
                throw
            }
            else {
                Write-Host "DNS zone group lookup for $peName exceeded the Azure PowerShell HTTP timeout. Waiting for it to finish..."
            }
        }

        if (-not $zoneGroupReady) {
            New-StoragePrivateDnsZoneGroup `
                -PrivateEndpointResourceId $privateEndpoint.Id `
                -PrivateEndpointName $peName `
                -GroupId $groupId `
                -PrivateDnsZoneId $zoneId
        }
    }
}

function Set-FunctionAppVnetIntegration {
    param(
        [string]$ResourceGroupName,
        [string]$FunctionAppName,
        [string]$SubnetResourceId,
        [bool]$EnableContentShare
    )

    $site = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceName $FunctionAppName -ResourceType "Microsoft.Web/sites" -ErrorAction Stop

    $siteProperties = @{
        virtualNetworkSubnetId = $SubnetResourceId
        vnetRouteAllEnabled    = $true
    }
    if ($EnableContentShare) {
        $siteProperties["vnetContentShareEnabled"] = $true
    }

    $sitePayload = @{ properties = $siteProperties } | ConvertTo-Json -Depth 5 -Compress
    $siteResult = Invoke-AzRestMethod -Path "$($site.ResourceId)?api-version=2023-12-01" -Method PATCH -Payload $sitePayload -ErrorAction Stop
    if ($siteResult.StatusCode -notin 200, 201, 202) {
        $detail = $siteResult.Content
        if ($detail -match 'Microsoft\.App') {
            $detail = "Flex VNet integration requires the Microsoft.App resource provider. Register it with a subscription Owner or Contributor, wait until RegistrationState is Registered, then rerun deploy: Register-AzResourceProvider -ProviderNamespace Microsoft.App"
        }
        throw "Failed to configure Function App VNet integration. ARM returned status $($siteResult.StatusCode): $detail"
    }

    $webPayload = @{
        properties = @{
            vnetRouteAllEnabled = $true
        }
    } | ConvertTo-Json -Depth 5 -Compress
    $webResult = Invoke-AzRestMethod -Path "$($site.ResourceId)/config/web?api-version=2023-12-01" -Method PATCH -Payload $webPayload -ErrorAction Stop
    if ($webResult.StatusCode -notin 200, 201, 202) {
        throw "Failed to enable VNet route-all. ARM returned status $($webResult.StatusCode): $($webResult.Content)"
    }

    Write-Host "Function App VNet integration and route-all configured" -ForegroundColor Green
}

# Flex OneDeploy writes the package from outside the VNet. Storage answers a blocked
# request with 404 "The specified resource does not exist." One PATCH sets public access
# and the default action together so a later network-rule update cannot turn public access back off.
function Get-StorageAccountNetworkProperties {
    param(
        [string]$ResourceGroupName,
        [string]$StorageAccountName
    )

    $account = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
    $result = Invoke-AzRestMethod -Path "$($account.Id)?api-version=2023-01-01" -Method GET -ErrorAction Stop
    if ($result.StatusCode -notin 200, 201) {
        throw "Failed to read storage account '$StorageAccountName'. ARM returned status $($result.StatusCode): $($result.Content)"
    }

    $body = $result.Content | ConvertFrom-Json
    return @{
        Id                  = $account.Id
        PublicNetworkAccess = [string]$body.properties.publicNetworkAccess
        NetworkAcls         = $body.properties.networkAcls
    }
}

function Enable-StoragePublicAccessForFlexDeploy {
    param(
        [string]$StorageAccountResourceGroup,
        [string]$StorageAccountName,
        [switch]$SkipPropagationWait
    )

    $current = Get-StorageAccountNetworkProperties -ResourceGroupName $StorageAccountResourceGroup -StorageAccountName $StorageAccountName
    $currentAction = if ($current.NetworkAcls) { [string]$current.NetworkAcls.defaultAction } else { "" }
    if ($current.PublicNetworkAccess -eq "Enabled" -and $currentAction -eq "Allow") {
        Write-Host "Storage public endpoint is already enabled (publicNetworkAccess=Enabled, defaultAction=Allow)" -ForegroundColor Green
        return
    }

    Write-Host "Temporarily enabling the storage public endpoint so Flex can upload the deployment package..."
    $bypass = "AzureServices"
    $ipRules = @()
    $vnetRules = @()
    if ($current.NetworkAcls) {
        if ($current.NetworkAcls.bypass) {
            $bypass = [string]$current.NetworkAcls.bypass
        }
        foreach ($rule in @($current.NetworkAcls.ipRules)) {
            if (-not $rule) { continue }
            $value = if ($rule.value) { [string]$rule.value } else { [string]$rule.iPAddressOrRange }
            if (-not $value) { continue }
            $action = if ($rule.action) { [string]$rule.action } else { "Allow" }
            $ipRules += @{ value = $value; action = $action }
        }
        foreach ($rule in @($current.NetworkAcls.virtualNetworkRules)) {
            if (-not $rule) { continue }
            $ruleId = if ($rule.id) { [string]$rule.id } else { [string]$rule.virtualNetworkResourceId }
            if (-not $ruleId) { continue }
            $action = if ($rule.action) { [string]$rule.action } else { "Allow" }
            $vnetRules += @{ id = $ruleId; action = $action }
        }
    }

    $payload = @{
        properties = @{
            publicNetworkAccess = "Enabled"
            networkAcls = @{
                defaultAction       = "Allow"
                bypass              = $bypass
                ipRules             = New-ArmJsonArray -Items $ipRules
                virtualNetworkRules = New-ArmJsonArray -Items $vnetRules
            }
        }
    }
    $payload = ConvertTo-ArmJson $payload

    $patch = Invoke-AzRestMethod -Path "$($current.Id)?api-version=2023-01-01" -Method PATCH -Payload $payload -ErrorAction Stop
    if ($patch.StatusCode -notin 200, 201, 202) {
        throw "Failed to enable storage public network access on '$StorageAccountName'. ARM returned status $($patch.StatusCode): $($patch.Content)"
    }

    $timeoutSeconds = 180
    $elapsed = 0
    $publicAccess = $null
    $defaultAction = $null
    do {
        Start-Sleep -Seconds 15
        $elapsed += 15
        $check = Get-StorageAccountNetworkProperties -ResourceGroupName $StorageAccountResourceGroup -StorageAccountName $StorageAccountName
        $publicAccess = $check.PublicNetworkAccess
        $defaultAction = if ($check.NetworkAcls) { [string]$check.NetworkAcls.defaultAction } else { "" }
        if ($publicAccess -eq "Enabled" -and $defaultAction -eq "Allow") {
            Write-Host "Storage public endpoint enabled (publicNetworkAccess=Enabled, defaultAction=Allow)" -ForegroundColor Green
            if (-not $SkipPropagationWait) {
                Write-Host "Waiting 30 seconds for the storage firewall change to propagate..."
                Start-Sleep -Seconds 30
            }
            return
        }
        Write-Host "Waiting for storage public access on ${StorageAccountName}... ($elapsed seconds, publicNetworkAccess=$publicAccess, defaultAction=$defaultAction)"
    } while ($elapsed -lt $timeoutSeconds)

    throw "Storage account '$StorageAccountName' did not stay publicly reachable for Flex deployment. Azure kept publicNetworkAccess=$publicAccess and defaultAction=$defaultAction."
}

function Set-StoragePublicAccessLockdown {
    param(
        [string]$StorageAccountResourceGroup,
        [string]$StorageAccountName,
        [object]$VirtualNetwork,
        [object]$IntegrationSubnet
    )

    $currentEndpoints = @()
    if ($IntegrationSubnet.ServiceEndpoints) {
        $currentEndpoints = @($IntegrationSubnet.ServiceEndpoints | ForEach-Object { $_.Service })
    }
    if ($currentEndpoints -notcontains "Microsoft.Storage") {
        Write-Host "Adding Microsoft.Storage service endpoint to $($IntegrationSubnet.Name)"
        $updatedEndpoints = $currentEndpoints + "Microsoft.Storage"
        $setParams = @{
            VirtualNetwork  = $VirtualNetwork
            Name            = $IntegrationSubnet.Name
            AddressPrefix   = $IntegrationSubnet.AddressPrefix
            ServiceEndpoint = $updatedEndpoints
        }
        if ($IntegrationSubnet.Delegations) {
            $setParams["Delegation"] = $IntegrationSubnet.Delegations
        }
        Set-AzVirtualNetworkSubnetConfig @setParams | Out-Null
        $VirtualNetwork | Set-AzVirtualNetwork | Out-Null
        $VirtualNetwork = Get-AzVirtualNetwork -ResourceGroupName $VirtualNetwork.ResourceGroupName -Name $VirtualNetwork.Name
        $IntegrationSubnet = $VirtualNetwork.Subnets | Where-Object { $_.Name -eq $IntegrationSubnet.Name } | Select-Object -First 1
    }

    try {
        Add-AzStorageAccountNetworkRule `
            -ResourceGroupName $StorageAccountResourceGroup `
            -Name $StorageAccountName `
            -VirtualNetworkResourceId $IntegrationSubnet.Id `
            -ErrorAction Stop | Out-Null
        Write-Host "Added storage network rule for $($IntegrationSubnet.Name)"
    }
    catch {
        $message = "$_"
        if ($message -notmatch '(?i)(already exists|already present|Conflict)') {
            throw
        }
        Write-Host "Storage network rule for $($IntegrationSubnet.Name) already exists"
    }

    Update-AzStorageAccountNetworkRuleSet `
        -ResourceGroupName $StorageAccountResourceGroup `
        -Name $StorageAccountName `
        -DefaultAction Deny | Out-Null

    Set-AzStorageAccount `
        -ResourceGroupName $StorageAccountResourceGroup `
        -Name $StorageAccountName `
        -PublicNetworkAccess Disabled | Out-Null

    Write-Host "Storage public network access disabled (default action Deny)" -ForegroundColor Green
}

function Assert-FlexDeploymentsContainer {
    param(
        [string]$ResourceGroupName,
        [string]$StorageAccountName,
        [int]$MaxAttempts = 5,
        [int]$RetryDelaySeconds = 15
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $account = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
            $deployContainer = Get-AzStorageContainer -Name "deployments" -Context $account.Context -ErrorAction SilentlyContinue
            if (-not $deployContainer) {
                New-AzStorageContainer -Name "deployments" -Context $account.Context -Permission Off -ErrorAction Stop | Out-Null
                Write-Host "Created deployments blob container" -ForegroundColor Green
            }
            return
        }
        catch {
            if ($attempt -ge $MaxAttempts) {
                throw "Failed to ensure the deployments container on storage account '${StorageAccountName}': $_"
            }
            Write-Host "Deployments container on $StorageAccountName is not reachable yet (attempt $attempt of $MaxAttempts). Retrying in $RetryDelaySeconds seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
}

function Repair-FlexDeploymentStorageConfig {
    param(
        [string]$ResourceGroupName,
        [string]$FunctionAppName,
        [string]$StorageAccountName,
        [string]$StorageEndpointSuffix
    )

    $expected = "https://$StorageAccountName.blob.$StorageEndpointSuffix/deployments".TrimEnd('/')
    $site = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceName $FunctionAppName -ResourceType "Microsoft.Web/sites" -ErrorAction Stop
    $get = Invoke-AzRestMethod -Path "$($site.ResourceId)?api-version=2023-12-01" -Method GET -ErrorAction Stop
    if ($get.StatusCode -notin 200, 201) {
        throw "Failed to read Function App '$FunctionAppName'. ARM returned status $($get.StatusCode): $($get.Content)"
    }

    $siteJson = $get.Content | ConvertFrom-Json
    $current = [string]$siteJson.properties.functionAppConfig.deployment.storage.value
    $currentNormalized = if ($current) { $current.TrimEnd('/') } else { "" }
    if ($currentNormalized -eq $expected) {
        Write-Host "Flex deployment storage URL is $expected"
        return
    }

    $shown = if ($current) { $current } else { "missing" }
    Write-Host "Repairing Flex deployment storage URL (current: $shown)..."
    $functionAppConfig = @{
        deployment = @{
            storage = @{
                type = "blobContainer"
                value = $expected
                authentication = @{
                    type = "StorageAccountConnectionString"
                    storageAccountConnectionStringName = "AzureWebJobsStorage"
                }
            }
        }
    }
    $existing = $siteJson.properties.functionAppConfig
    if ($existing -and $existing.scaleAndConcurrency) {
        $functionAppConfig.scaleAndConcurrency = $existing.scaleAndConcurrency
    }
    if ($existing -and $existing.runtime) {
        $functionAppConfig.runtime = $existing.runtime
    }

    $payload = @{ properties = @{ functionAppConfig = $functionAppConfig } } | ConvertTo-Json -Depth 10 -Compress
    $patch = Invoke-AzRestMethod -Path "$($site.ResourceId)?api-version=2023-12-01" -Method PATCH -Payload $payload -ErrorAction Stop
    if ($patch.StatusCode -notin 200, 201, 202) {
        throw "Failed to set Flex deployment storage URL. ARM returned status $($patch.StatusCode): $($patch.Content)"
    }
    Write-Host "Flex deployment storage URL set to $expected" -ForegroundColor Green
}

function Set-FlexPowerShellRuntime {
    param(
        [string]$ResourceGroupName,
        [string]$FunctionAppName,
        [string]$Version = "7.6"
    )

    $site = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceName $FunctionAppName -ResourceType "Microsoft.Web/sites" -ErrorAction Stop
    $get = Invoke-AzRestMethod -Path "$($site.ResourceId)?api-version=2023-12-01" -Method GET -ErrorAction Stop
    if ($get.StatusCode -notin 200, 201) {
        throw "Failed to read Function App '$FunctionAppName'. ARM returned status $($get.StatusCode): $($get.Content)"
    }

    $siteJson = $get.Content | ConvertFrom-Json
    $existing = $siteJson.properties.functionAppConfig
    $currentName = [string]$existing.runtime.name
    $currentVersion = [string]$existing.runtime.version
    if ($currentName -eq "powershell" -and $currentVersion -eq $Version) {
        Write-Host "Flex PowerShell runtime is already $Version"
        return
    }

    Write-Host "Setting Flex PowerShell runtime to $Version..."
    $functionAppConfig = @{
        runtime = @{
            name    = "powershell"
            version = $Version
        }
    }
    if ($existing -and $existing.deployment) {
        $functionAppConfig.deployment = $existing.deployment
    }
    if ($existing -and $existing.scaleAndConcurrency) {
        $functionAppConfig.scaleAndConcurrency = $existing.scaleAndConcurrency
    }

    $payload = @{ properties = @{ functionAppConfig = $functionAppConfig } } | ConvertTo-Json -Depth 10 -Compress
    $patch = Invoke-AzRestMethod -Path "$($site.ResourceId)?api-version=2023-12-01" -Method PATCH -Payload $payload -ErrorAction Stop
    if ($patch.StatusCode -notin 200, 201, 202) {
        throw "Failed to set Flex PowerShell runtime to $Version. ARM returned status $($patch.StatusCode): $($patch.Content)"
    }

    $deadline = (Get-Date).AddSeconds(60)
    do {
        $confirm = Invoke-AzRestMethod -Path "$($site.ResourceId)?api-version=2023-12-01" -Method GET -ErrorAction Stop
        if ($confirm.StatusCode -in 200, 201) {
            $confirmed = ($confirm.Content | ConvertFrom-Json).properties.functionAppConfig.runtime
            if ([string]$confirmed.name -eq "powershell" -and [string]$confirmed.version -eq $Version) {
                Write-Host "Flex PowerShell runtime set to $Version" -ForegroundColor Green
                return
            }
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)

    throw "Function App '$FunctionAppName' did not report PowerShell runtime $Version after the update."
}

function Complete-FlexCreateAndLockNetworking {
    param(
        [string]$ResourceGroupName,
        [string]$Location,
        [string]$FunctionAppName,
        [string]$StorageAccountName,
        [string]$StorageAccountResourceGroup,
        [string]$StorageEndpointSuffix,
        [object]$SecureNetworking
    )

    Write-Host "Configuring private DNS zones and storage private endpoints..."
    Set-StoragePrivateDnsAndEndpoints `
        -ResourceGroupName $ResourceGroupName `
        -Location $Location `
        -StorageAccountName $StorageAccountName `
        -StorageAccountResourceGroup $StorageAccountResourceGroup `
        -PrivateEndpointSubnet $SecureNetworking.PrivateEndpointSubnet `
        -VirtualNetwork $SecureNetworking.VirtualNetwork `
        -StorageEndpointSuffix $StorageEndpointSuffix

    Write-Host "Configuring Function App VNet integration..."
    Set-FunctionAppVnetIntegration `
        -ResourceGroupName $ResourceGroupName `
        -FunctionAppName $FunctionAppName `
        -SubnetResourceId $SecureNetworking.IntegrationSubnetId `
        -EnableContentShare $false

    Write-Host "Locking storage account public network access..."
    Set-StoragePublicAccessLockdown `
        -StorageAccountResourceGroup $StorageAccountResourceGroup `
        -StorageAccountName $StorageAccountName `
        -VirtualNetwork $SecureNetworking.VirtualNetwork `
        -IntegrationSubnet $SecureNetworking.IntegrationSubnet
}

# Set default App Service Plan Resource Group if not specified
if (-not $AppServicePlanResourceGroup) {
    $AppServicePlanResourceGroup = $ResourceGroupName
}
if (-not $StorageAccountResourceGroup) {
    $StorageAccountResourceGroup = $ResourceGroupName
}
if (-not $VNetResourceGroup) {
    $VNetResourceGroup = $ResourceGroupName
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

function Test-TransientFlexDeployFailure {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return $false
    }

    return $Message -match '(?i)(InaccessibleStorageException|BlobUploadFailedException|Resource temporarily unavailable|timed?\s*out|timeout|status(?:\s*code)?\D{0,12}50[23]|\(50[23]\)|HTTP/?\s*50[23])'
}

function Get-FlexDeployFailureSummary {
    param([string]$Message)

    if ($Message -match '(?i)((?:InaccessibleStorageException|BlobUploadFailedException):\s*[^'']+|Resource temporarily unavailable[^'']*)') {
        $summary = $Matches[1].Trim()
    }
    else {
        $summary = ($Message -replace '\s+', ' ').Trim()
    }

    if ($summary.Length -gt 400) {
        return $summary.Substring(0, 400)
    }

    return $summary
}

function Invoke-AzCliConfigZip {
    param(
        [string]$ResourceGroupName,
        [string]$FunctionAppName,
        [string]$ZipPath
    )

    # A non-zero az exit is a deploy result, not a terminating PowerShell error.
    $PSNativeCommandUseErrorActionPreference = $false
    $nativeOutput = & az functionapp deployment source config-zip `
        --resource-group $ResourceGroupName `
        --name $FunctionAppName `
        --src $ZipPath `
        --only-show-errors 2>&1
    $exitCode = $LASTEXITCODE

    return @{
        ExitCode = $exitCode
        Output   = ($nativeOutput | Out-String)
    }
}

function Invoke-ScmFlexOneDeploy {
    param(
        [string]$ResourceGroupName,
        [string]$FunctionAppName,
        [string]$ZipPath,
        [string]$PublishUrl
    )

    try {
        $accessToken = Get-AzAccessTokenString
        Write-Host "Attempting SCM OneDeploy with AAD token..."
        Invoke-RestMethod -Uri $PublishUrl `
            -Method POST `
            -Headers @{ Authorization = "Bearer $accessToken" } `
            -InFile $ZipPath `
            -ContentType "application/zip" `
            -ErrorAction Stop | Out-Null
        return
    }
    catch {
        $aadError = "$_"
        if (Test-TransientFlexDeployFailure -Message $aadError) {
            throw
        }
        Write-Host "AAD OneDeploy failed, trying basic auth: $aadError" -ForegroundColor Yellow
    }

    $publishingCredentials = Invoke-AzResourceAction -ResourceGroupName $ResourceGroupName `
        -ResourceType Microsoft.Web/sites/config `
        -ResourceName "$FunctionAppName/publishingcredentials" `
        -Action list -Force
    $username = $publishingCredentials.Properties.PublishingUserName
    $password = $publishingCredentials.Properties.PublishingPassword
    $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${username}:${password}"))

    Invoke-RestMethod -Uri $PublishUrl `
        -Method POST `
        -Headers @{ Authorization = "Basic $base64Auth" } `
        -InFile $ZipPath `
        -ContentType "application/zip" `
        -ErrorAction Stop | Out-Null
}

# Flex OneDeploy can fail while a storage firewall change is still propagating.
# Re-open public access between Azure CLI retries, then fall back to SCM OneDeploy.
function Publish-FlexFunctionPackage {
    param(
        [string]$ResourceGroupName,
        [string]$FunctionAppName,
        [string]$ZipPath,
        [string]$PublishUrl,
        [string]$StorageAccountResourceGroup,
        [string]$StorageAccountName,
        [switch]$ReopenStorageOnTransientError,
        [int]$MaxAttempts = 5,
        [int]$RetryDelaySeconds = 30
    )

    $useAzCli = [bool](Get-Command az -ErrorAction SilentlyContinue)
    if (-not $useAzCli) {
        Write-Host "Azure CLI not found. Using SCM OneDeploy..." -ForegroundColor Yellow
    }

    if ($useAzCli) {
        for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
            Write-Host "Attempting Azure CLI config-zip deploy (attempt $attempt of $MaxAttempts)..."
            $result = Invoke-AzCliConfigZip `
                -ResourceGroupName $ResourceGroupName `
                -FunctionAppName $FunctionAppName `
                -ZipPath $ZipPath
            if ($result.ExitCode -eq 0) {
                Write-Host "Function code deployed successfully via Azure CLI" -ForegroundColor Green
                return
            }

            $message = [string]$result.Output
            $summary = Get-FlexDeployFailureSummary -Message $message
            if (-not (Test-TransientFlexDeployFailure -Message $message)) {
                if (-not [string]::IsNullOrWhiteSpace($message)) {
                    Write-Host $message
                }
                throw "Azure CLI config-zip deploy failed: $summary"
            }

            Write-Host "Transient storage error on attempt $attempt of ${MaxAttempts}: $summary" -ForegroundColor Yellow
            if ($ReopenStorageOnTransientError -and $attempt -lt $MaxAttempts) {
                Enable-StoragePublicAccessForFlexDeploy `
                    -StorageAccountResourceGroup $StorageAccountResourceGroup `
                    -StorageAccountName $StorageAccountName `
                    -SkipPropagationWait
            }

            if ($attempt -lt $MaxAttempts) {
                Write-Host "Storage is not reachable yet. Retrying zip publish in $RetryDelaySeconds seconds..."
                Start-Sleep -Seconds $RetryDelaySeconds
            }
        }

        Write-Host "Azure CLI zip publish did not complete. Trying SCM OneDeploy..." -ForegroundColor Yellow
        if ($ReopenStorageOnTransientError) {
            Enable-StoragePublicAccessForFlexDeploy `
                -StorageAccountResourceGroup $StorageAccountResourceGroup `
                -StorageAccountName $StorageAccountName `
                -SkipPropagationWait
        }

        try {
            Invoke-ScmFlexOneDeploy `
                -ResourceGroupName $ResourceGroupName `
                -FunctionAppName $FunctionAppName `
                -ZipPath $ZipPath `
                -PublishUrl $PublishUrl
            Write-Host "Function code deployed successfully via SCM OneDeploy" -ForegroundColor Green
            return
        }
        catch {
            $summary = Get-FlexDeployFailureSummary -Message "$_"
            throw "Flex zip publish failed after $MaxAttempts Azure CLI attempts and SCM OneDeploy. $summary"
        }
    }

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Write-Host "Attempting SCM OneDeploy (attempt $attempt of $MaxAttempts)..."
            Invoke-ScmFlexOneDeploy `
                -ResourceGroupName $ResourceGroupName `
                -FunctionAppName $FunctionAppName `
                -ZipPath $ZipPath `
                -PublishUrl $PublishUrl
            Write-Host "Function code deployed successfully via SCM OneDeploy" -ForegroundColor Green
            return
        }
        catch {
            $message = "$_"
            $summary = Get-FlexDeployFailureSummary -Message $message
            if (-not (Test-TransientFlexDeployFailure -Message $message)) {
                throw
            }

            Write-Host "Transient storage error on attempt $attempt of ${MaxAttempts}: $summary" -ForegroundColor Yellow
            if ($ReopenStorageOnTransientError -and $attempt -lt $MaxAttempts) {
                Enable-StoragePublicAccessForFlexDeploy `
                    -StorageAccountResourceGroup $StorageAccountResourceGroup `
                    -StorageAccountName $StorageAccountName `
                    -SkipPropagationWait
            }
        }

        if ($attempt -lt $MaxAttempts) {
            Write-Host "Storage is not reachable yet. Retrying zip publish in $RetryDelaySeconds seconds..."
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }

    throw "Flex zip publish failed after $MaxAttempts attempts because storage was still unreachable."
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
    Write-Host "Hosting plan: Flex Consumption (Linux, PowerShell 7.6)$resolutionNote" -ForegroundColor Cyan
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

$secureStorageMode = Resolve-SecureStorageMode `
    -StorageAccountName $StorageAccountName `
    -VNetName $VNetName `
    -IntegrationSubnetName $IntegrationSubnetName `
    -PrivateEndpointSubnetName $PrivateEndpointSubnetName
$secureNetworking = $null

if ($secureStorageMode -eq "Public") {
    if ([string]::IsNullOrWhiteSpace($StorageAccountName)) {
        $StorageAccountName = Get-ValidStorageAccountName -FunctionAppName $FunctionAppName
    }
    Write-Host "Storage path: public (default)"
}
elseif ($secureStorageMode -eq "Existing") {
    Write-Host "Storage path: existing account $StorageAccountName (VNet integration only)" -ForegroundColor Cyan
}
else {
    if ([string]::IsNullOrWhiteSpace($StorageAccountName)) {
        $StorageAccountName = Get-ValidStorageAccountName -FunctionAppName $FunctionAppName
    }
    Write-Host "Storage path: create-and-lock $StorageAccountName" -ForegroundColor Cyan
}

if ($secureStorageMode -ne "Public") {
    Assert-SecureStorageModules
    $secureNetworking = Test-SecureStorageNetworkingPrereqs `
        -VNetResourceGroup $VNetResourceGroup `
        -VNetName $VNetName `
        -IntegrationSubnetName $IntegrationSubnetName `
        -PrivateEndpointSubnetName $PrivateEndpointSubnetName `
        -IsFlexConsumption $isFlexConsumption `
        -RequirePrivateEndpointSubnet ($secureStorageMode -eq "CreateAndLock")
}

Write-Host "Using storage account name: $StorageAccountName"

# Create or resolve the storage account
Write-Host "Resolving Storage Account..."
$storageAccount = New-OrGetFunctionStorageAccount `
    -ResourceGroupName $StorageAccountResourceGroup `
    -StorageAccountName $StorageAccountName `
    -Location $Location `
    -Mode $secureStorageMode

$deferFlexPrivateNetworking = ($secureStorageMode -eq "CreateAndLock" -and $isFlexConsumption)
if ($secureStorageMode -eq "CreateAndLock" -and -not $deferFlexPrivateNetworking) {
    Write-Host "Configuring private DNS zones and storage private endpoints..."
    Set-StoragePrivateDnsAndEndpoints `
        -ResourceGroupName $ResourceGroupName `
        -Location $Location `
        -StorageAccountName $StorageAccountName `
        -StorageAccountResourceGroup $StorageAccountResourceGroup `
        -PrivateEndpointSubnet $secureNetworking.PrivateEndpointSubnet `
        -VirtualNetwork $secureNetworking.VirtualNetwork `
        -StorageEndpointSuffix $storageEndpointSuffix
}
elseif ($deferFlexPrivateNetworking) {
    Write-Host "Flex create-and-lock publishes the package before private endpoints, while storage is still public."
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
    if ($secureStorageMode -ne "Public" -and $AzureCloud -ne "AzureUSGovernment") {
        throw "Secure storage requires regional VNet integration, which Consumption (Y1) does not support. Pass -AppServicePlanName for a Basic or Premium plan, or use -HostingPlan FlexConsumption."
    }
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

if ($secureStorageMode -ne "Public") {
    Assert-SecureStorageHostingPlan -AppServicePlan $appServicePlan -IsFlexConsumption $isFlexConsumption
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
    Write-Host "  Runtime: PowerShell 7.6"

    $storageConnectionString = Get-StorageAccountConnectionString -ResourceGroupName $StorageAccountResourceGroup -StorageAccountName $StorageAccountName -EndpointSuffix $storageEndpointSuffix

    # Flex Consumption: Linux app created with functionAppConfig (not classic worker-runtime app settings)
    if ($isFlexConsumption) {
        Write-Host "Creating Flex Consumption Function App (Linux) via ARM..." -ForegroundColor Yellow

        # Ensure deployment container exists
        if ($deferFlexPrivateNetworking) {
            Enable-StoragePublicAccessForFlexDeploy `
                -StorageAccountResourceGroup $StorageAccountResourceGroup `
                -StorageAccountName $StorageAccountName `
                -SkipPropagationWait
        }
        Assert-FlexDeploymentsContainer `
            -ResourceGroupName $StorageAccountResourceGroup `
            -StorageAccountName $StorageAccountName

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
                    version = "7.6"
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
            $storageInDifferentRg = $StorageAccountResourceGroup -ne $ResourceGroupName

            if ($isConsumption -or $storageInDifferentRg) {
                if ($isConsumption) {
                    Write-Host "Detected Consumption plan (Y1) - using ARM deployment..." -ForegroundColor Yellow
                }
                else {
                    Write-Host "Storage account is in a different resource group - using ARM deployment..." -ForegroundColor Yellow
                }

                # Consumption plans have issues with New-AzFunctionApp trying to set AlwaysOn
                # Use ARM API for Windows Consumption
                $functionAppProperties = @{
                    serverFarmId = $appServicePlan.Id
                    siteConfig = @{
                        appSettings = @(
                            @{ name = "AzureWebJobsStorage"; value = $storageConnectionString }
                            @{ name = "FUNCTIONS_WORKER_RUNTIME"; value = "powershell" }
                            @{ name = "FUNCTIONS_WORKER_RUNTIME_VERSION"; value = "7.6" }
                            @{ name = "FUNCTIONS_EXTENSION_VERSION"; value = "~4" }
                            @{ name = "APPLICATIONINSIGHTS_CONNECTION_STRING"; value = $appInsightsConnectionString }
                            @{ name = "APPINSIGHTS_INSTRUMENTATIONKEY"; value = $appInsightsInstrumentationKey }
                        )
                        powerShellVersion = "7.6"
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
                    -RuntimeVersion "7.6" `
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

if ($secureStorageMode -ne "Public" -and -not $deferFlexPrivateNetworking) {
    Write-Host "Configuring Function App VNet integration..."
    Set-FunctionAppVnetIntegration `
        -ResourceGroupName $ResourceGroupName `
        -FunctionAppName $FunctionAppName `
        -SubnetResourceId $secureNetworking.IntegrationSubnetId `
        -EnableContentShare (-not $isFlexConsumption)
}

# Configure runtime versions with retry logic (Classic only — Flex uses functionAppConfig + ARM settings)
Write-Host "Configuring runtime versions..."
if (-not $isFlexConsumption) {
    $runtimeSettings = @{
        "FUNCTIONS_WORKER_RUNTIME"         = "powershell"
        "FUNCTIONS_WORKER_RUNTIME_VERSION" = "7.6"
        "FUNCTIONS_EXTENSION_VERSION"      = "~4"
        "WEBSITE_RUN_FROM_PACKAGE"         = "0"  # Enable in-portal editing
        "WEBSITE_HTTPSONLY"               = "1"  # Force HTTPS
    }

    $retryCount = 0
    $maxRetries = 5
    while ($retryCount -lt $maxRetries) {
        try {
            Update-AzFunctionAppSetting -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -AppSetting $runtimeSettings -Confirm:$false -ErrorAction Stop
            $classicSite = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceName $FunctionAppName -ResourceType "Microsoft.Web/sites" -ErrorAction Stop
            $psPayload = @{ properties = @{ siteConfig = @{ powerShellVersion = "7.6" } } } | ConvertTo-Json -Depth 5 -Compress
            $psPatch = Invoke-AzRestMethod -Path "$($classicSite.ResourceId)?api-version=2023-12-01" -Method PATCH -Payload $psPayload -ErrorAction Stop
            if ($psPatch.StatusCode -notin 200, 201, 202) {
                throw "ARM returned status $($psPatch.StatusCode): $($psPatch.Content)"
            }
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
    Set-FlexPowerShellRuntime -ResourceGroupName $ResourceGroupName -FunctionAppName $FunctionAppName
    Start-Sleep -Seconds 10
}

# Configure environment variables
Write-Host "Configuring environment variables..."
$storageConnectionString = Get-StorageAccountConnectionString -ResourceGroupName $StorageAccountResourceGroup -StorageAccountName $StorageAccountName -EndpointSuffix $storageEndpointSuffix
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
    $settings["FUNCTIONS_WORKER_RUNTIME_VERSION"] = "7.6"
}

if ($isFlexConsumption) {
    Write-Host "Applying app settings via ARM (Flex-safe)..."
    Set-FunctionAppSettingsViaArm -ResourceGroupName $ResourceGroupName -FunctionAppName $FunctionAppName -Settings $settings
    Write-Host "App settings applied via ARM" -ForegroundColor Green
}
else {
    Update-AzFunctionAppSetting -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -AppSetting $settings -Confirm:$false
}

$lockStorageAfterFlexDeploy = ($secureStorageMode -eq "CreateAndLock" -and $isFlexConsumption)
if ($lockStorageAfterFlexDeploy) {
    Enable-StoragePublicAccessForFlexDeploy `
        -StorageAccountResourceGroup $StorageAccountResourceGroup `
        -StorageAccountName $StorageAccountName
    Assert-FlexDeploymentsContainer `
        -ResourceGroupName $StorageAccountResourceGroup `
        -StorageAccountName $StorageAccountName
    Repair-FlexDeploymentStorageConfig `
        -ResourceGroupName $ResourceGroupName `
        -FunctionAppName $FunctionAppName `
        -StorageAccountName $StorageAccountName `
        -StorageEndpointSuffix $storageEndpointSuffix
}
elseif ($secureStorageMode -eq "CreateAndLock") {
    Write-Host "Locking storage account public network access..."
    Set-StoragePublicAccessLockdown `
        -StorageAccountResourceGroup $StorageAccountResourceGroup `
        -StorageAccountName $StorageAccountName `
        -VirtualNetwork $secureNetworking.VirtualNetwork `
        -IntegrationSubnet $secureNetworking.IntegrationSubnet
}

# Deploy function code
Write-Host "Deploying function code..."

$deploySucceeded = $false
$storageRelocked = $false
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
        $profilePath = Join-Path $srcPath "profile.ps1"
        if (Test-Path $profilePath) {
            Copy-Item -Path $profilePath -Destination $tempDir
        }

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

        $publishParams = @{
            ResourceGroupName = $ResourceGroupName
            FunctionAppName   = $FunctionAppName
            ZipPath           = $zipPath
            PublishUrl        = $publishUrl
        }
        if ($lockStorageAfterFlexDeploy) {
            $publishParams["StorageAccountResourceGroup"] = $StorageAccountResourceGroup
            $publishParams["StorageAccountName"] = $StorageAccountName
            $publishParams["ReopenStorageOnTransientError"] = $true
        }
        Publish-FlexFunctionPackage @publishParams

        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue

        if ($lockStorageAfterFlexDeploy) {
            Complete-FlexCreateAndLockNetworking `
                -ResourceGroupName $ResourceGroupName `
                -Location $Location `
                -FunctionAppName $FunctionAppName `
                -StorageAccountName $StorageAccountName `
                -StorageAccountResourceGroup $StorageAccountResourceGroup `
                -StorageEndpointSuffix $storageEndpointSuffix `
                -SecureNetworking $secureNetworking
            $storageRelocked = $true
        }

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

    # Replace the platform profile.ps1 that calls Az.Accounts (not installed)
    $profilePath = Join-Path $srcPath "profile.ps1"
    if (Test-Path $profilePath) {
        $profilePs1 = Get-Content -Path $profilePath -Raw
        Invoke-WithRetry -Uri "$apiUrl/site/wwwroot/profile.ps1" `
            -Headers @{Authorization="Basic $base64Auth"} `
            -Method PUT `
            -Body $profilePs1 `
            -ContentType "text/plain"
    }

        Write-Host "Function code deployed successfully"
    }

    # Restart the Function App
    Write-Host "Restarting Function App..."
    Restart-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -Force

    # Basic/dedicated plans (and Gov) often need longer before /functions is populated
    Write-Host "Waiting 30 seconds for function host to index after restart..."
    Start-Sleep -Seconds 30
    Assert-ForwarderDeployment -ResourceGroupName $ResourceGroupName -FunctionAppName $FunctionAppName
    $deploySucceeded = $true
}
catch {
    Write-Host "Failed to deploy function code: $_" -ForegroundColor Red
    throw
}
finally {
    if ($lockStorageAfterFlexDeploy -and -not $storageRelocked) {
        try {
            Write-Host "Locking storage account public network access..."
            Set-StoragePublicAccessLockdown `
                -StorageAccountResourceGroup $StorageAccountResourceGroup `
                -StorageAccountName $StorageAccountName `
                -VirtualNetwork $secureNetworking.VirtualNetwork `
                -IntegrationSubnet $secureNetworking.IntegrationSubnet
        }
        catch {
            Write-Host "Failed to disable storage public network access: $_" -ForegroundColor Red
            if ($deploySucceeded) {
                throw "Function code deployed, but storage public network access is still enabled. Disable it on '$StorageAccountName' before leaving the account open."
            }
        }
    }
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
Write-Host "- Storage Account: $StorageAccountName ($secureStorageMode)"
Write-Host "- Extension Bundle: v4.x (latest)"
Write-Host "- System-assigned managed identity: Enabled (attempted)"
if ($secureStorageMode -ne "Public") {
    Write-Host "- Function App VNet integration: $VNetName / $IntegrationSubnetName"
} 
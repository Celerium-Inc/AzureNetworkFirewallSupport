# Cleanup script for Azure Firewall Blocklist Integration Function
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$FunctionAppName
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

Write-Host "Starting cleanup process..."
Write-Host "Resource Group: $ResourceGroupName"
Write-Host "Function App: $FunctionAppName"

# Generate storage account name
$StorageAccountName = Get-ValidStorageAccountName -FunctionAppName $FunctionAppName
Write-Host "Storage Account: $StorageAccountName"

# Generate Application Insights name
$AppInsightsName = "$FunctionAppName-insights"
Write-Host "Application Insights: $AppInsightsName"

# Prompt for confirmation
$confirmation = Read-Host "Are you sure you want to delete these resources? (y/n)"
if ($confirmation -ne 'y') {
    Write-Host "Cleanup cancelled by user"
    exit 0
}

# Function to ensure we have a valid Azure context
function Ensure-AzureConnection {
    try {
        $context = Get-AzContext
        if (-not $context) {
            Write-Host "No Azure context found. Connecting..."
            Connect-AzAccount -UseDeviceAuthentication
            $context = Get-AzContext
        }
        
        if (-not $context) {
            throw "Failed to establish Azure connection"
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to connect to Azure: $_" -ForegroundColor Red
        return $false
    }
}

# Ensure we're connected before proceeding
if (-not (Ensure-AzureConnection)) {
    Write-Host "Cannot proceed without Azure connection" -ForegroundColor Red
    exit 1
}

# Remove Function App
try {
    Write-Host "Removing Function App $FunctionAppName..."
    Remove-AzFunctionApp -Name $FunctionAppName -ResourceGroupName $ResourceGroupName -Force
    Write-Host "Function App removed successfully"
}
catch {
    Write-Host "Error removing Function App: $_" -ForegroundColor Red
}

# Remove Storage Account
try {
    Write-Host "Removing Storage Account $StorageAccountName..."
    Remove-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -Force
    Write-Host "Storage Account removed successfully"
}
catch {
    Write-Host "Error removing Storage Account: $_" -ForegroundColor Red
}

# Remove Application Insights
try {
    Write-Host "Removing Application Insights $AppInsightsName..."
    Remove-AzApplicationInsights -ResourceGroupName $ResourceGroupName -Name $AppInsightsName
    Write-Host "Application Insights removed successfully"
}
catch {
    Write-Host "Error removing Application Insights: $_" -ForegroundColor Red
}

Write-Host "Cleanup completed!" 
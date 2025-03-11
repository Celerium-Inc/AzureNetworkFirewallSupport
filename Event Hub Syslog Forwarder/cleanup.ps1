# Cleanup script for Event Hub Syslog Forwarder
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$FunctionAppName,
    
    [Parameter(Mandatory = $true)]
    [string]$StorageAccountName
)

# Error handling
$ErrorActionPreference = 'Stop'

Write-Host "Starting cleanup process..."
Write-Host "Resource Group: $ResourceGroupName"
Write-Host "Function App: $FunctionAppName"
Write-Host "Storage Account: $StorageAccountName"

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

Write-Host "Cleanup completed!" 
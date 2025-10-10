# This script processes Azure Event Hub messages containing various log types (Flow Logs, DNS Queries, DNS Responses, Firewall Logs)
# and forwards them to a syslog server over SSL or UDP based on configuration.

param(
    [Parameter(Mandatory = $true)]
    [Array]$eventHubMessages
)

# Validate required environment variables
if (-not $env:SYSLOG_SERVER) {
    throw "SYSLOG_SERVER environment variable is not set"
}

if (-not $env:SYSLOG_PORT) {
    throw "SYSLOG_PORT environment variable is not set"
}

# Get protocol from environment variable (defaults to SSL if not specified)
$protocol = if ($env:SYSLOG_PROTOCOL) { $env:SYSLOG_PROTOCOL.ToUpper() } else { "SSL" }
if ($protocol -notin @("SSL", "UDP")) {
    throw "SYSLOG_PROTOCOL must be either 'SSL' or 'UDP'"
}

# Get syslog server connection details from environment variables
$syslogServer = $env:SYSLOG_SERVER
$syslogPort = [int]$env:SYSLOG_PORT

# Log the function start with configuration
Write-Host "Function triggered at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Using Syslog Server: $syslogServer"
Write-Host "Using Syslog Port: $syslogPort"
Write-Host "Using Protocol: $protocol"
Write-Host "Number of events received: $($eventHubMessages.Count)"

if (-not $eventHubMessages)
{
    Write-Host "No events received."
    return
}

# Debug: Log the type of the first message
Write-Host "First message type: $($eventHubMessages[0].GetType().FullName)"
Write-Host "First message content: $($eventHubMessages[0] | ConvertTo-Json -Depth 5)"

# Counter for successfully processed events
$successfullyProcessedCount = 0

#region Utility Functions

# Function to send message to syslog with error handling
function SendToSyslog
{
    param (
        [string]$Message,    # The formatted syslog message to send
        [string]$Server,     # Syslog server hostname/IP
        [int]$Port,         # Syslog server port
        [string]$Protocol   # SSL or UDP
    )
    try
    {
        if ($Protocol -eq "SSL") {
            # Establish a TCP connection for SSL
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $networkStream = $null
            $sslStream = $null
            
            try {
                $tcpClient.Connect($Server, $Port)
                $networkStream = $tcpClient.GetStream()

                # Wrap the network stream with an SSL stream
                $sslStream = New-Object System.Net.Security.SslStream($networkStream, $false, { $true }) # Accepts any cert, change if needed
                $sslStream.AuthenticateAsClient($Server)

                # Convert message to bytes and send over SSL
                $syslogBytes = [System.Text.Encoding]::UTF8.GetBytes($Message + "`n")
                $sslStream.Write($syslogBytes, 0, $syslogBytes.Length)
                $sslStream.Flush()
            }
            finally {
                # Ensure proper cleanup of resources
                if ($sslStream) { $sslStream.Close() }
                if ($networkStream) { $networkStream.Close() }
                if ($tcpClient) { $tcpClient.Close() }
            }
        }
        else {
            # Send over UDP
            $udpClient = New-Object System.Net.Sockets.UdpClient
            try {
                $syslogBytes = [System.Text.Encoding]::UTF8.GetBytes($Message)
                $udpClient.Send($syslogBytes, $syslogBytes.Length, $Server, $Port) | Out-Null
            }
            finally {
                $udpClient.Close()
            }
        }

        Write-Host "Sent message to syslog over $Protocol`: $Message"
    }
    catch
    {
        Write-Error "Failed to send message to syslog over $Protocol`: $_"
    }
}

# Function to convert timestamps to RFC3339 format (ISO 8601) with UTC timezone
function ConvertTo-RFC3339
{
    param (
        [string]$timestamp  # Input timestamp to be converted
    )
    try
    {
        if (-not [string]::IsNullOrEmpty($timestamp))
        {
            $dateTime = [DateTime]::Parse($timestamp).ToUniversalTime()
            return $dateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
        else
        {
            throw "Timestamp is empty or null."
        }
    }
    catch
    {
        Write-Error "Failed to convert timestamp: $timestamp - Error: $_"
        return $timestamp  # Return original timestamp as a fallback
    }
}

#endregion

#region Log Processing Functions

# Function to parse DestPublicIps for ExternalPublic and AzurePublic flow types
function Parse-DestPublicIps
{
    param (
        [string]$FlowType,           # The flow type (for logging purposes)
        [string]$DestPublicIps,      # The DestPublicIps field content
        [string]$FlowDirection,      # Flow direction (Inbound/Outbound)
        [string]$L7Protocol          # L7 protocol (HTTP, HTTPS, Unknown, etc.)
    )
    
    $publicIpEntries = @()
    
    # Filter: Skip AzurePublic flows with Inbound direction and Unknown L7Protocol
    if ($FlowType -eq "AzurePublic" -and $FlowDirection -eq "Inbound" -and $L7Protocol -eq "Unknown") {
        Write-Host "Skipping AzurePublic Inbound flow with Unknown L7Protocol"
        return @()
    }
    
    # Parse DestPublicIps format: Multiple space-separated entries, only extract indexes 0 (IP), 5 (outbound bytes), 6 (inbound bytes)
    if ($DestPublicIps -and $DestPublicIps -ne "") {
        $destPublicIpsEntries = $DestPublicIps -split ' '
        foreach ($entry in $destPublicIpsEntries) {
            if ($entry -and $entry.Trim() -ne "") {
                $entryParts = $entry -split '\|'
                if ($entryParts.Length -ge 7) {
                    $publicIpAddress = $entryParts[0]
                    $outboundBytes = $entryParts[5]
                    $inboundBytes = $entryParts[6]
                    
                    # Only include entries with actual traffic (non-zero bytes)
                    try {
                        $outboundBytesInt = [int]$outboundBytes
                        $inboundBytesInt = [int]$inboundBytes
                        
                        if ($outboundBytesInt -gt 0 -or $inboundBytesInt -gt 0) {
                            $publicIpEntries += @{
                                PublicIp = $publicIpAddress
                                OutboundBytes = $outboundBytes
                                InboundBytes = $inboundBytes
                            }
                            Write-Host "Parsed DestPublicIp entry: IP=$publicIpAddress, OutboundBytes=$outboundBytes, InboundBytes=$inboundBytes"
                        }
                    }
                    catch {
                        Write-Warning "Failed to parse byte values for entry $entry`: $_"
                    }
                } else {
                    Write-Warning "DestPublicIps entry format is invalid: $entry"
                }
            }
        }
        Write-Host "Found $($publicIpEntries.Count) DestPublicIps entries with traffic for $FlowType flow"
    } else {
        Write-Warning "DestPublicIps field is empty or missing for $FlowType flow type"
    }
    
    return $publicIpEntries
}

# Function to process Virtual Network Flow Logs
function Process-FlowLog
{
    param (
        [PSCustomObject]$record
    )
    
    $syslogMessages = @()
    
    # Process Virtual Network Flow Logs
    # These logs contain information about traffic flows through NSGs
    $timestamp = ConvertTo-RFC3339 -timestamp $record.TimeGenerated
    $timeProcessed = ConvertTo-RFC3339 -timestamp $record.TimeProcessed
    $flowIntervalStart = ConvertTo-RFC3339 -timestamp $record.FlowIntervalStartTime
    $flowIntervalEnd = ConvertTo-RFC3339 -timestamp $record.FlowIntervalEndTime
    $flowStartTime = ConvertTo-RFC3339 -timestamp $record.FlowStartTime
    $flowEndTime = ConvertTo-RFC3339 -timestamp $record.FlowEndTime

    # Extract and map fields from the payload
    $faSchemaVersion = $record.FaSchemaVersion
    $isFlowCapturedAtUdrHop = $record.IsFlowCapturedAtUdrHop
    $srcIp = $record.SrcIp
    $destIp = $record.DestIp
    $destPort = $record.DestPort
    $flowType = $record.FlowType
    $bytesDestToSrc = $record.BytesDestToSrc
    $bytesSrcToDest = $record.BytesSrcToDest
    
    $protocol = $record.L4Protocol
    $l7Protocol = $record.L7Protocol
    $flowDirection = $record.FlowDirection
    
    # Parse DestPublicIps only for ExternalPublic or AzurePublic flow types
    $publicIpEntries = @()
    if ($flowType -eq "ExternalPublic" -or $flowType -eq "AzurePublic") {
        $publicIpEntries = Parse-DestPublicIps -FlowType $flowType -DestPublicIps $record.DestPublicIps -FlowDirection $flowDirection -L7Protocol $l7Protocol
    }
    $flowStatus = $record.FlowStatus
    $macAddress = $record.MacAddress
    $flowLogResourceId = $record.FlowLogResourceId
    $targetResourceId = $record.TargetResourceId
    $targetResourceType = $record.TargetResourceType

    # Map destination-related fields (renamed to Dest* to match payload)
    $destSubscription = $record.DestSubscription
    $destRegion = $record.DestRegion
    $destNic = $record.DestNic
    $destVm = $record.DestVm
    $destSubnet = $record.DestSubnet

    $flowEncryption = $record.FlowEncryption
    $allowedInFlows = $record.AllowedInFlows
    $deniedInFlows = $record.DeniedInFlows
    $allowedOutFlows = $record.AllowedOutFlows
    $deniedOutFlows = $record.DeniedOutFlows
    $packetsDestToSrc = $record.PacketsDestToSrc
    $packetsSrcToDest = $record.PacketsSrcToDest
    $completedFlows = $record.CompletedFlows
    $aclGroup = $record.AclGroup
    $aclRule = $record.AclRule

    # Additional fields from the payload
    $itemId = $record._ItemId
    $workspaceResourceId = $record._Internal_WorkspaceResourceId
    $eventType = $record.Type
    $tenantId = $record.TenantId

    # Create syslog message template (reusable for all entries)
    $syslogTemplate = "<13>TimeGenerated=${timestamp} Type=FlowLog FaSchemaVersion=${faSchemaVersion} " +             `
                          "TimeProcessed=${timeProcessed} FlowIntervalStart=${flowIntervalStart} FlowIntervalEnd=${flowIntervalEnd} " +             `
                          "FlowStartTime=${flowStartTime} FlowEndTime=${flowEndTime} FlowType=${flowType} " +             `
                          "IsFlowCapturedAtUdrHop=${isFlowCapturedAtUdrHop} SrcIp=${srcIp} DstIp={0} DstPort=${destPort} " +             `
                          "Protocol=${protocol} L7Protocol=${l7Protocol} Direction=${flowDirection} Status=${flowStatus} " +             `
                          "MacAddress=${macAddress} FlowLogResourceId=${flowLogResourceId} TargetResourceId=${targetResourceId} " +             `
                          "TargetResourceType=${targetResourceType} DestSubscription=${destSubscription} DestRegion=${destRegion} " +             `
                          "DestNic=${destNic} DestVm=${destVm} DestSubnet=${destSubnet} FlowEncryption=${flowEncryption} " +             `
                          "AllowedInFlows=${allowedInFlows} DeniedInFlows=${deniedInFlows} AllowedOutFlows=${allowedOutFlows} " +             `
                          "DeniedOutFlows=${deniedOutFlows} PacketsDestToSrc=${packetsDestToSrc} PacketsSrcToDest=${packetsSrcToDest} " +             `
                          "BytesDestToSrc={1} BytesSrcToDest={2} CompletedFlows=${completedFlows} " +             `
                          "AclGroup=${aclGroup} AclRule=${aclRule} ItemId=${itemId} WorkspaceResourceId=${workspaceResourceId} " +             `
                          "EventType=${eventType} TenantId=${tenantId}"

    # Generate syslog messages using the template
    if ($publicIpEntries.Count -gt 0) {
        # Create separate syslog messages for each public IP entry with traffic
        foreach ($publicIpEntry in $publicIpEntries) {
            $syslogMessage = $syslogTemplate -f $publicIpEntry.PublicIp, $publicIpEntry.InboundBytes, $publicIpEntry.OutboundBytes
            $syslogMessages += $syslogMessage
        }
    } else {
        # Use original data when no public IP entries with traffic are found
        $syslogMessage = $syslogTemplate -f $destIp, $bytesDestToSrc, $bytesSrcToDest
        $syslogMessages += $syslogMessage
    }
    
    return $syslogMessages
}

# Function to process Azure Firewall DNS Query Logs
function Process-DnsQueryLog
{
    param (
        [PSCustomObject]$record
    )
    
    $syslogMessages = @()
    
    # Process Azure Firewall DNS Query Logs
    # These logs contain information about DNS queries processed by Azure Firewall
    $timestamp = ConvertTo-RFC3339 -timestamp $record.time
    $resourceId = $record.resourceId
    $sourceIp = $record.properties.SourceIp
    $sourcePort = $record.properties.SourcePort
    $queryId = $record.properties.QueryId
    $queryType = $record.properties.QueryType
    $queryClass = $record.properties.QueryClass
    $queryName = $record.properties.QueryName
    $protocol = $record.properties.Protocol
    $requestSize = $record.properties.RequestSize
    $dnssecOkBit = $record.properties.DnssecOkBit
    $edns0BufferSize = $record.properties.EDNS0BufferSize
    $responseCode = $record.properties.ResponseCode
    $responseFlags = $record.properties.ResponseFlags
    $responseSize = $record.properties.ResponseSize
    $requestDurationSecs = $record.properties.RequestDurationSecs
    $errorNumber = $record.properties.ErrorNumber
    $errorMessage = $record.properties.ErrorMessage

    # Format the syslog message for DNS logs
    $syslogMessage = "<13>TimeGenerated=${timestamp} Type=DnsQueryLog " +             `
                         "ResourceId=${resourceId} SrcIp=${sourceIp} SrcPort=${sourcePort} QueryId=${queryId} " +             `
                         "QueryType=${queryType} QueryClass=${queryClass} QueryName=${queryName} Protocol=${protocol} " +             `
                         "RequestSize=${requestSize} DnssecOkBit=${dnssecOkBit} EDNS0BufferSize=${edns0BufferSize} " +             `
                         "ResponseCode=${responseCode} ResponseFlags=${responseFlags} ResponseSize=${responseSize} " +             `
                         "RequestDurationSecs=${requestDurationSecs} ErrorNumber=${errorNumber} ErrorMessage=${errorMessage}"
    $syslogMessages += $syslogMessage
    
    return $syslogMessages
}

# Function to process Azure Firewall DNS Response Logs
function Process-DnsResponseLog
{
    param (
        [PSCustomObject]$record
    )
    
    $syslogMessages = @()
    
    # Process Azure Firewall DNS Response Logs
    # These logs contain detailed information about DNS responses including answer records
    $timestamp = ConvertTo-RFC3339 -timestamp $record.time
    $resourceId = $record.resourceId
    $operationName = $record.operationName
    $version = $record.properties.version
    $subId = $record.properties.sub_id
    $region = $record.properties.region
    $vnetId = $record.properties.vnet_id
    $queryName = $record.properties.query_name
    $queryType = $record.properties.query_type
    $queryClass = $record.properties.query_class
    $responseCode = $record.properties.response_code
    $srcIpAddr = $record.properties.srcipaddr
    $srcPort = $record.properties.srcport
    $dstIpAddr = $record.properties.dstipaddr
    $dstPort = $record.properties.dstport
    $transport = $record.properties.transport
    $queryResponseTime = $record.properties.query_response_time
    $resolutionPath = $record.properties.resolution_path
    $resolverPolicyId = $record.properties.resolverpolicy_id
    $resolverPolicyRuleAction = $record.properties.resolverpolicy_rule_action

    # Process each DNS answer in the response
    $answerIndex = 0
    foreach ($answer in $record.properties.answer)
    {
        try
        {
            $dnsAnswerType = $answer.Type
            $dnsAnswerClass = $answer.Class
            $dnsAnswerTTL = $answer.TTL
            $dnsAnswerRData = $answer.RData

            # Format the syslog message for each answer
            $syslogMessage = "<13>TimeGenerated=${timestamp} Type=DnsResponseLog " +  `
                                 "ResourceId=${resourceId} OperationName=${operationName} Version=${version} " +  `
                                 "SubId=${subId} Region=${region} VnetId=${vnetId} QueryName=${queryName} " +  `
                                 "QueryType=${queryType} QueryClass=${queryClass} ResponseCode=${responseCode} " +  `
                                 "SrcIpAddr=${srcIpAddr} SrcPort=${srcPort} DstIpAddr=${dstIpAddr} DstPort=${dstPort} " +  `
                                 "Transport=${transport} QueryResponseTime=${queryResponseTime} ResolutionPath=${resolutionPath} " +  `
                                 "ResolverPolicyId=${resolverPolicyId} ResolverPolicyRuleAction=${resolverPolicyRuleAction} " +  `
                                 "DnsAnswerIndex=${answerIndex} DnsAnswerType=${dnsAnswerType} DnsAnswerClass=${dnsAnswerClass} " +  `
                                 "DnsAnswerTTL=${dnsAnswerTTL} DnsAnswerRData=${dnsAnswerRData}"

            # Add message to the array
            $syslogMessages += $syslogMessage

            # Increment answer index
            $answerIndex++
        }
        catch
        {
            Write-Error "Error processing DNS answer: $_"
        }
    }
    
    return $syslogMessages
}

# Function to process Azure Firewall Network/Application Rules Logs
function Process-FirewallLog
{
    param (
        [PSCustomObject]$record
    )
    
    $syslogMessages = @()
    
    # Process Azure Firewall Network/Application Rules Logs
    # These logs contain information about traffic allowed/denied by firewall rules
    $timestamp = ConvertTo-RFC3339 -timestamp $record.time
    $resourceId = $record.resourceId
    $protocol = $record.properties.Protocol
    $sourceIp = $record.properties.SourceIp
    $sourcePort = $record.properties.SourcePort
    $destinationIp = $record.properties.DestinationIp
    $destinationPort = $record.properties.DestinationPort
    $action = $record.properties.Action
    $policy = $record.properties.Policy
    $ruleCollectionGroup = $record.properties.RuleCollectionGroup
    $ruleCollection = $record.properties.RuleCollection
    $rule = $record.properties.Rule
    $actionReason = $record.properties.ActionReason

    # Format the syslog message
    $syslogMessage = "<13>TimeGenerated=${timestamp} Type=FirewallLog " +             `
                         "ResourceId=${resourceId} Protocol=${protocol} SrcIp=${sourceIp} SrcPort=${sourcePort} " +             `
                         "DstIp=${destinationIp} DstPort=${destinationPort} Action=${action} " +             `
                         "Policy=${policy} RuleCollectionGroup=${ruleCollectionGroup} RuleCollection=${ruleCollection} " +             `
                         "Rule=${rule} ActionReason=${actionReason}"
    $syslogMessages += $syslogMessage
    
    return $syslogMessages
}

#endregion

#region Main Processing Logic

# Process each event from the Event Hub message batch
foreach ($event in $eventHubMessages)
{
    try
    {
        # Array to store formatted syslog messages before sending
        $syslogMessages = @()

        # Log the raw event for debugging
        Write-Host "Processing event: $( $event | ConvertTo-Json -Depth 10 )"

        # Convert the event to a PowerShell object if it's not already
        try {
            if ($event -is [string]) {
                $message = $event | ConvertFrom-Json
            } else {
                $message = $event
            }
        }
        catch {
            Write-Error "Failed to process event: $( $event ) - Error: $_"
            continue  # Skip this event and move to the next
        }

        # Ensure we have records to process
        if (-not $message.records) {
            Write-Error "No records found in message"
            continue
        }

        # Process each record based on log type
        foreach ($record in $message.records)
        {
            # Handle different log types by calling appropriate processing functions:
            # 1. Virtual Network Flow Logs (SubType = FlowLog)
            # 2. Azure Firewall DNS Query Logs (category = AZFWDnsQuery)
            # 3. Azure Firewall DNS Response Logs (category = DnsResponse)
            # 4. Azure Firewall Network/Application Rules Logs (default case)

            if ($record.SubType -eq "FlowLog")
            {
                $recordMessages = Process-FlowLog -record $record
                $syslogMessages += $recordMessages
            }
            elseif ($record.category -eq "AZFWDnsQuery")
            {
                $recordMessages = Process-DnsQueryLog -record $record
                $syslogMessages += $recordMessages
            }
            elseif ($record.category -eq "DnsResponse")
            {
                $recordMessages = Process-DnsResponseLog -record $record
                $syslogMessages += $recordMessages
            }
            else
            {
                $recordMessages = Process-FirewallLog -record $record
                $syslogMessages += $recordMessages
            }
        }

        # Increment successfully processed count
        $successfullyProcessedCount++

    }
    catch
    {
        Write-Error "Error processing event: $( $event | ConvertTo-Json -Depth 10 ) - Error: $_"
    }

    # Send all collected syslog messages for this event
    foreach ($syslogMessage in $syslogMessages)
    {
        try
        {
            SendToSyslog -Message $syslogMessage -Server $syslogServer -Port $syslogPort -Protocol $protocol
        }
        catch
        {
            Write-Error "Failed to send syslog message: $_"
        }
    }
}

# Log summary of processed events
Write-Host "Successfully processed $successfullyProcessedCount out of $( $eventHubMessages.Length ) event(s)."

#endregion

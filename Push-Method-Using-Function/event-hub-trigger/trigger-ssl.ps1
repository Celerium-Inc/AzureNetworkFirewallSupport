# This script processes Azure Event Hub messages containing various log types (Flow Logs, DNS Queries, DNS Responses, Firewall Logs)
# and forwards them to a syslog server over SSL. It handles message parsing, formatting, and secure transmission.

param(
    [Parameter(Mandatory = $true)]
    [Array]$eventHubMessages  # Array of messages received from Azure Event Hub
)

# Syslog server connection details
$syslogServer = "dev2-d3-syslog.cdndev.net"
$syslogPort = 40678

# Log the function start
Write-Host "Function triggered at $( Get-Date -Format 'yyyy-MM-dd HH:mm:ss' )"

if (-not $eventHubMessages)
{
    Write-Host "No events received."
    return
}

# Counter for successfully processed events
$successfullyProcessedCount = 0

# Function to send message to syslog with error handling
function SendToSyslogOverSSL
{
    param (
        [string]$Message,    # The formatted syslog message to send
        [string]$Server,     # Syslog server hostname/IP
        [int]$Port          # Syslog server port
    )
    try
    {
        # Establish a TCP connection
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($Server, $Port)
        $networkStream = $tcpClient.GetStream()

        # Wrap the network stream with an SSL stream
        $sslStream = New-Object System.Net.Security.SslStream($networkStream, $false, { $true }) # Accepts any cert, change if needed
        $sslStream.AuthenticateAsClient($Server)

        # Convert message to bytes and send over SSL
        $syslogBytes = [System.Text.Encoding]::UTF8.GetBytes($Message + "`n")
        $sslStream.Write($syslogBytes, 0, $syslogBytes.Length)
        $sslStream.Flush()

        # Close the stream and connection
        $sslStream.Close()
        $networkStream.Close()
        $tcpClient.Close()

        Write-Host "Sent message to syslog over SSL: $Message"
    }
    catch
    {
        Write-Error "Failed to send message to syslog over SSL: $_"
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

# Process each event from the Event Hub message batch
foreach ($event in $eventHubMessages)
{
    try
    {
        # Array to store formatted syslog messages before sending
        $syslogMessages = @()

        # Log the raw event for debugging
        Write-Host "Processing event: $( $event | ConvertTo-Json -Depth 10 )"

        # Check if the event is already a hashtable
        if ($event -is [System.Management.Automation.OrderedHashtable])
        {
            $message = $event
        }
        else
        {
            # Try deserializing the JSON message
            try
            {
                $message = $event | ConvertFrom-Json
            }
            catch
            {
                Write-Error "Failed to deserialize event: $( $event ) - Error: $_"
                continue  # Skip this event and move to the next
            }
        }

        # Process each record based on log type
        foreach ($record in $message.records)
        {
            # Handle different log types:
            # 1. Virtual Network Flow Logs (SubType = FlowLog)
            # 2. Azure Firewall DNS Query Logs (category = AZFWDnsQuery)
            # 3. Azure Firewall DNS Response Logs (category = DnsResponse)
            # 4. Azure Firewall Network/Application Rules Logs (default case)
            
            if ($record.SubType -eq "FlowLog")
            {
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
                # For the source IP, split the SrcPublicIps string and take the first element
                $srcIp = ($record.SrcPublicIps -split "\|")[0]
                $destIp = $record.DestIp
                $destPort = $record.DestPort
                $flowType = $record.FlowType
                $protocol = $record.L4Protocol
                $l7Protocol = $record.L7Protocol
                $flowDirection = $record.FlowDirection
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
                $bytesDestToSrc = $record.BytesDestToSrc
                $bytesSrcToDest = $record.BytesSrcToDest
                $completedFlows = $record.CompletedFlows
                $aclGroup = $record.AclGroup
                $aclRule = $record.AclRule

                # Additional fields from the payload
                $itemId = $record._ItemId
                $workspaceResourceId = $record._Internal_WorkspaceResourceId
                $eventType = $record.Type
                $tenantId = $record.TenantId

                # Format the syslog message with all fields
                $syslogMessage = "<13>TimeGenerated=${timestamp} Type=FlowLog FaSchemaVersion=${faSchemaVersion} " +             `
                                     "TimeProcessed=${timeProcessed} FlowIntervalStart=${flowIntervalStart} FlowIntervalEnd=${flowIntervalEnd} " +             `
                                     "FlowStartTime=${flowStartTime} FlowEndTime=${flowEndTime} FlowType=${flowType} " +             `
                                     "IsFlowCapturedAtUdrHop=${isFlowCapturedAtUdrHop} SrcIp=${srcIp} DstIp=${destIp} DstPort=${destPort} " +             `
                                     "Protocol=${protocol} L7Protocol=${l7Protocol} Direction=${flowDirection} Status=${flowStatus} " +             `
                                     "MacAddress=${macAddress} FlowLogResourceId=${flowLogResourceId} TargetResourceId=${targetResourceId} " +             `
                                     "TargetResourceType=${targetResourceType} DestSubscription=${destSubscription} DestRegion=${destRegion} " +             `
                                     "DestNic=${destNic} DestVm=${destVm} DestSubnet=${destSubnet} FlowEncryption=${flowEncryption} " +             `
                                     "AllowedInFlows=${allowedInFlows} DeniedInFlows=${deniedInFlows} AllowedOutFlows=${allowedOutFlows} " +             `
                                     "DeniedOutFlows=${deniedOutFlows} PacketsDestToSrc=${packetsDestToSrc} PacketsSrcToDest=${packetsSrcToDest} " +             `
                                     "BytesDestToSrc=${bytesDestToSrc} BytesSrcToDest=${bytesSrcToDest} CompletedFlows=${completedFlows} " +             `
                                     "AclGroup=${aclGroup} AclRule=${aclRule} ItemId=${itemId} WorkspaceResourceId=${workspaceResourceId} " +             `
                                     "EventType=${eventType} TenantId=${tenantId}"
                $syslogMessages += $syslogMessage

            }
            elseif ($record.category -eq "AZFWDnsQuery")
            {
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

            }
            elseif ($record.category -eq "DnsResponse")
            {
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

                        # Add message to the global array
                        $syslogMessages += $syslogMessage

                        # Increment answer index
                        $answerIndex++
                    }
                    catch
                    {
                        Write-Error "Error processing DNS answer: $_"
                    }
                }
            }
            else
            {
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
            }
        }

        # Increment successfully processed count
        $successfullyProcessedCount++

    }
    catch
    {
        Write-Error "Error processing record: $( $record | ConvertTo-Json -Depth 10 ) - Error: $_"
    }

    # Send all collected syslog messages for this event
    foreach ($syslogMessage in $syslogMessages)
    {
        try
        {
            SendToSyslogOverSSL -Message $syslogMessage -Server $syslogServer -Port $syslogPort
        }
        catch
        {
            Write-Error "Failed to send syslog message: $_"
        }
    }
}

# Log summary of processed events
Write-Host "Successfully processed $successfullyProcessedCount out of $( $eventHubMessages.Length ) event(s)."

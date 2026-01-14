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

function Get-IntEnvOrDefault {
    param(
        [string]$Name,
        [int]$DefaultValue
    )

    $raw = (Get-Item -Path ("env:{0}" -f $Name) -ErrorAction SilentlyContinue).Value
    if ([string]::IsNullOrWhiteSpace($raw)) { return $DefaultValue }

    $val = 0
    if ([int]::TryParse($raw, [ref]$val)) { return $val }
    return $DefaultValue
}

function Close-SyslogSslSession {
    param(
        [hashtable]$Session
    )
    try {
        if ($Session.SslStream)     { $Session.SslStream.Close() }
    } catch {}
    try {
        if ($Session.NetworkStream) { $Session.NetworkStream.Close() }
    } catch {}
    try {
        if ($Session.TcpClient)    { $Session.TcpClient.Close() }
    } catch {}
}

function New-SyslogSslSession {
    param(
        [string]$Server,
        [int]$Port,
        [int]$ConnectTimeoutMs,
        [int]$IoTimeoutMs
    )

    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $networkStream = $null
    $sslStream = $null

    # Fail-fast connect using async wait handle
    $iar = $tcpClient.BeginConnect($Server, $Port, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne($ConnectTimeoutMs, $false)) {
        $tcpClient.Close()
        throw "TCP connect timed out after ${ConnectTimeoutMs}ms to $Server`:$Port"
    }
    $tcpClient.EndConnect($iar)

    # Apply IO timeouts on the socket
    $tcpClient.SendTimeout    = $IoTimeoutMs
    $tcpClient.ReceiveTimeout = $IoTimeoutMs

    $networkStream = $tcpClient.GetStream()
    $networkStream.ReadTimeout  = $IoTimeoutMs
    $networkStream.WriteTimeout = $IoTimeoutMs

    # Wrap the network stream with an SSL stream
    # NOTE: This accepts any cert (your prior behavior). Tighten this later if/when you have the CA/thumbprint.
    $sslStream = New-Object System.Net.Security.SslStream($networkStream, $false, { $true })

    # Authenticate SSL (uses underlying stream timeouts)
    $sslStream.AuthenticateAsClient($Server)

    return @{
        TcpClient     = $tcpClient
        NetworkStream = $networkStream
        SslStream     = $sslStream
    }
}

# NEW: Send a whole batch over a single connection (Fix B) + retries/backoff (Fix A)
function SendToSyslogBatch
{
    param (
        [string[]]$Messages,
        [string]$Server,
        [int]$Port,
        [string]$Protocol
    )

    if (-not $Messages -or $Messages.Count -eq 0) {
        return $true
    }

    # Timeouts (your existing Fix #1 behavior)
    $connectTimeoutMs = Get-IntEnvOrDefault -Name "SYSLOG_CONNECT_TIMEOUT_MS" -DefaultValue 5000
    $ioTimeoutMs      = Get-IntEnvOrDefault -Name "SYSLOG_IO_TIMEOUT_MS"      -DefaultValue 5000

    # Retries/backoff (Fix A)
    $maxRetries       = Get-IntEnvOrDefault -Name "SYSLOG_MAX_RETRIES"         -DefaultValue 3
    $baseBackoffMs    = Get-IntEnvOrDefault -Name "SYSLOG_RETRY_BACKOFF_MS"    -DefaultValue 500
    $maxBackoffMs     = Get-IntEnvOrDefault -Name "SYSLOG_RETRY_BACKOFF_MAX_MS" -DefaultValue 5000

    try {
        if ($Protocol -eq "SSL") {

            $startIndex = 0
            for ($attempt = 0; $attempt -le $maxRetries; $attempt++) {
                $session = $null
                try {
                    $session = New-SyslogSslSession -Server $Server -Port $Port -ConnectTimeoutMs $connectTimeoutMs -IoTimeoutMs $ioTimeoutMs

                    for ($i = $startIndex; $i -lt $Messages.Count; $i++) {
                        $msg = $Messages[$i]
                        $bytes = [System.Text.Encoding]::UTF8.GetBytes($msg + "`n")
                        $session.SslStream.Write($bytes, 0, $bytes.Length)
                    }

                    $session.SslStream.Flush()

                    # Success
                    Write-Host "Sent batch to syslog over SSL: count=$($Messages.Count)"
                    Close-SyslogSslSession -Session $session
                    return $true
                }
                catch {
                    $err = $_

                    Write-Error "Failed to send batch to syslog over SSL (attempt $attempt of $maxRetries): $err"

                    if ($session) { Close-SyslogSslSession -Session $session }

                    if ($attempt -lt $maxRetries) {
                        $sleepMs = [Math]::Min($maxBackoffMs, ($baseBackoffMs * ($attempt + 1)))
                        Start-Sleep -Milliseconds $sleepMs
                        continue
                    }

                    # Give up after retries
                    return $false
                }
            }
        }
        else {
            # UDP (unchanged conceptually, but reuse a single udp client per batch)
            $udpClient = New-Object System.Net.Sockets.UdpClient
            try {
                $udpClient.Client.SendTimeout = $ioTimeoutMs

                for ($attempt = 0; $attempt -le $maxRetries; $attempt++) {
                    try {
                        foreach ($msg in $Messages) {
                            $bytes = [System.Text.Encoding]::UTF8.GetBytes($msg)
                            $udpClient.Send($bytes, $bytes.Length, $Server, $Port) | Out-Null
                        }

                        Write-Host "Sent batch to syslog over UDP: count=$($Messages.Count)"
                        return $true
                    }
                    catch {
                        Write-Error "Failed to send batch to syslog over UDP (attempt $attempt of $maxRetries): $_"
                        if ($attempt -lt $maxRetries) {
                            $sleepMs = [Math]::Min($maxBackoffMs, ($baseBackoffMs * ($attempt + 1)))
                            Start-Sleep -Milliseconds $sleepMs
                            continue
                        }
                        return $false
                    }
                }
            }
            finally {
                $udpClient.Close()
            }
        }
    }
    catch {
        Write-Error "SendToSyslogBatch unexpected error: $_"
        return $false
    }
}

# Kept for compatibility (still works), but main path now uses SendToSyslogBatch (Fix B)
function SendToSyslog
{
    param (
        [string]$Message,
        [string]$Server,
        [int]$Port,
        [string]$Protocol
    )
    [void](SendToSyslogBatch -Messages @($Message) -Server $Server -Port $Port -Protocol $Protocol)
}

# Function to convert timestamps to RFC3339 format (ISO 8601) with UTC timezone
function ConvertTo-RFC3339
{
    param (
        [string]$timestamp
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
        return $timestamp
    }
}

# NEW PATCH: works for PSCustomObject AND Hashtable/OrderedHashtable records
function Resolve-RecordTimestampRfc3339 {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Record,

        [string[]]$PreferredFields = @("time", "TimeGenerated", "TimeProcessed", "_TimeReceived"),

        [switch]$LogFallback
    )

    function Get-FieldValue {
        param([object]$Obj, [string]$Field)

        # Hashtable / OrderedHashtable
        if ($Obj -is [System.Collections.IDictionary]) {
            if ($Obj.Contains($Field)) {
                return [string]$Obj[$Field]
            }
            return $null
        }

        # PSCustomObject / normal object properties
        try {
            $p = $Obj.PSObject.Properties[$Field]
            if ($null -ne $p) { return [string]$p.Value }
        } catch {}

        # Last attempt: dot access (some adapters)
        try {
            $v = $Obj.$Field
            if ($null -ne $v) { return [string]$v }
        } catch {}

        return $null
    }

    $rawTs = $null
    foreach ($field in $PreferredFields) {
        $val = Get-FieldValue -Obj $Record -Field $field
        if (-not [string]::IsNullOrWhiteSpace($val)) {
            $rawTs = $val
            break
        }
    }

    if ([string]::IsNullOrWhiteSpace($rawTs)) {
        $rawTs = (Get-Date).ToUniversalTime().ToString("o")  # always parseable
        if ($LogFallback) {
            $keys = $null
            if ($Record -is [System.Collections.IDictionary]) {
                $keys = ($Record.Keys | ForEach-Object { $_.ToString() } | Sort-Object) -join ", "
            } else {
                $keys = ($Record.PSObject.Properties.Name | Sort-Object) -join ", "
            }
            Write-Warning "No usable timestamp on record; using current UTC time. RecordType=$($Record.GetType().FullName) Keys=$keys"
        }
    }

    return ConvertTo-RFC3339 -timestamp $rawTs
}

#endregion

#region Log Processing Functions

function Parse-DestPublicIps
{
    param (
        [string]$FlowType,
        [string]$DestPublicIps,
        [string]$FlowDirection,
        [string]$L7Protocol
    )

    $publicIpEntries = @()

    if ($FlowType -eq "AzurePublic" -and $FlowDirection -eq "Inbound" -and $L7Protocol -eq "Unknown") {
        Write-Host "Skipping AzurePublic Inbound flow with Unknown L7Protocol"
        return @()
    }

    if ($DestPublicIps -and $DestPublicIps -ne "") {
        $destPublicIpsEntries = $DestPublicIps -split ' '
        foreach ($entry in $destPublicIpsEntries) {
            if ($entry -and $entry.Trim() -ne "") {
                $entryParts = $entry -split '\|'
                if ($entryParts.Length -ge 7) {
                    $publicIpAddress = $entryParts[0]
                    $outboundBytes = $entryParts[5]
                    $inboundBytes = $entryParts[6]

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

function Process-FlowLog
{
    param (
        $record
    )

    $syslogMessages = @()

    # Use robust timestamp resolver
    $timestamp         = Resolve-RecordTimestampRfc3339 -Record $record -PreferredFields @("TimeGenerated","time","_TimeReceived") -LogFallback
    $timeProcessed     = Resolve-RecordTimestampRfc3339 -Record $record -PreferredFields @("TimeProcessed","TimeGenerated","time","_TimeReceived")
    $flowIntervalStart = Resolve-RecordTimestampRfc3339 -Record $record -PreferredFields @("FlowIntervalStartTime","TimeGenerated","time","_TimeReceived")
    $flowIntervalEnd   = Resolve-RecordTimestampRfc3339 -Record $record -PreferredFields @("FlowIntervalEndTime","TimeGenerated","time","_TimeReceived")
    $flowStartTime     = Resolve-RecordTimestampRfc3339 -Record $record -PreferredFields @("FlowStartTime","TimeGenerated","time","_TimeReceived")
    $flowEndTime       = Resolve-RecordTimestampRfc3339 -Record $record -PreferredFields @("FlowEndTime","TimeGenerated","time","_TimeReceived")

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

    $publicIpEntries = @()
    if ($flowType -eq "ExternalPublic" -or $flowType -eq "AzurePublic") {
        $publicIpEntries = Parse-DestPublicIps -FlowType $flowType -DestPublicIps $record.DestPublicIps -FlowDirection $flowDirection -L7Protocol $l7Protocol
    }

    $flowStatus = $record.FlowStatus
    $macAddress = $record.MacAddress
    $flowLogResourceId = $record.FlowLogResourceId
    $targetResourceId = $record.TargetResourceId
    $targetResourceType = $record.TargetResourceType

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

    $itemId = $record._ItemId
    $workspaceResourceId = $record._Internal_WorkspaceResourceId
    $eventType = $record.Type
    $tenantId = $record.TenantId

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

    if ($publicIpEntries.Count -gt 0) {
        foreach ($publicIpEntry in $publicIpEntries) {
            $syslogMessage = $syslogTemplate -f $publicIpEntry.PublicIp, $publicIpEntry.InboundBytes, $publicIpEntry.OutboundBytes
            $syslogMessages += $syslogMessage
        }
    } else {
        $syslogMessage = $syslogTemplate -f $destIp, $bytesDestToSrc, $bytesSrcToDest
        $syslogMessages += $syslogMessage
    }

    return $syslogMessages
}

function Process-DnsQueryLog
{
    param (
        $record
    )

    $syslogMessages = @()

    $timestamp = Resolve-RecordTimestampRfc3339 -Record $record -PreferredFields @("time","TimeGenerated","_TimeReceived") -LogFallback
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

    $syslogMessage = "<13>TimeGenerated=${timestamp} Type=DnsQueryLog " +             `
                         "ResourceId=${resourceId} SrcIp=${sourceIp} SrcPort=${sourcePort} QueryId=${queryId} " +             `
                         "QueryType=${queryType} QueryClass=${queryClass} QueryName=${queryName} Protocol=${protocol} " +             `
                         "RequestSize=${requestSize} DnssecOkBit=${dnssecOkBit} EDNS0BufferSize=${edns0BufferSize} " +             `
                         "ResponseCode=${responseCode} ResponseFlags=${responseFlags} ResponseSize=${responseSize} " +             `
                         "RequestDurationSecs=${requestDurationSecs} ErrorNumber=${errorNumber} ErrorMessage=${errorMessage}"
    $syslogMessages += $syslogMessage

    return $syslogMessages
}

function Process-DnsResponseLog
{
    param (
        $record
    )

    $syslogMessages = @()

    $timestamp = Resolve-RecordTimestampRfc3339 -Record $record -PreferredFields @("time","TimeGenerated","_TimeReceived") -LogFallback
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

    $answerIndex = 0
    foreach ($answer in $record.properties.answer)
    {
        try
        {
            $dnsAnswerType = $answer.Type
            $dnsAnswerClass = $answer.Class
            $dnsAnswerTTL = $answer.TTL
            $dnsAnswerRData = $answer.RData

            $syslogMessage = "<13>TimeGenerated=${timestamp} Type=DnsResponseLog " +  `
                                 "ResourceId=${resourceId} OperationName=${operationName} Version=${version} " +  `
                                 "SubId=${subId} Region=${region} VnetId=${vnetId} QueryName=${queryName} " +  `
                                 "QueryType=${queryType} QueryClass=${queryClass} ResponseCode=${responseCode} " +  `
                                 "SrcIpAddr=${srcIpAddr} SrcPort=${srcPort} DstIpAddr=${dstIpAddr} DstPort=${dstPort} " +  `
                                 "Transport=${transport} QueryResponseTime=${queryResponseTime} ResolutionPath=${resolutionPath} " +  `
                                 "ResolverPolicyId=${resolverPolicyId} ResolverPolicyRuleAction=${resolverPolicyRuleAction} " +  `
                                 "DnsAnswerIndex=${answerIndex} DnsAnswerType=${dnsAnswerType} DnsAnswerClass=${dnsAnswerClass} " +  `
                                 "DnsAnswerTTL=${dnsAnswerTTL} DnsAnswerRData=${dnsAnswerRData}"

            $syslogMessages += $syslogMessage
            $answerIndex++
        }
        catch
        {
            Write-Error "Error processing DNS answer: $_"
        }
    }

    return $syslogMessages
}

function Process-FirewallLog
{
    param (
        $record
    )

    $syslogMessages = @()

    $timestamp = Resolve-RecordTimestampRfc3339 -Record $record -PreferredFields @("time","TimeGenerated","_TimeReceived") -LogFallback
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

foreach ($event in $eventHubMessages)
{
    $syslogMessages = @()

    try
    {
        Write-Host "Processing event: $( $event | ConvertTo-Json -Depth 10 )"

        try {
            if ($event -is [string]) {
                $message = $event | ConvertFrom-Json
            } else {
                $message = $event
            }
        }
        catch {
            Write-Error "Failed to process event: $( $event ) - Error: $_"
            continue
        }

        if (-not $message.records) {
            Write-Error "No records found in message"
            continue
        }

        foreach ($record in $message.records)
        {
            if ($record.SubType -eq "FlowLog")
            {
                $syslogMessages += (Process-FlowLog -record $record)
            }
            elseif ($record.category -eq "AZFWDnsQuery")
            {
                $syslogMessages += (Process-DnsQueryLog -record $record)
            }
            elseif ($record.category -eq "DnsResponse")
            {
                $syslogMessages += (Process-DnsResponseLog -record $record)
            }
            else
            {
                $syslogMessages += (Process-FirewallLog -record $record)
            }
        }

        $successfullyProcessedCount++
    }
    catch
    {
        Write-Error "Error processing event: $( $event | ConvertTo-Json -Depth 10 ) - Error: $_"
    }

    # Fix B: send this event's syslog messages in ONE batch (single SSL connection)
    if ($syslogMessages.Count -gt 0) {
        $ok = SendToSyslogBatch -Messages $syslogMessages -Server $syslogServer -Port $syslogPort -Protocol $protocol
        if (-not $ok) {
            # Keep behavior: log error but do not throw (so invocation doesn't fail solely due to syslog target issues)
            Write-Error "Batch send to syslog failed after retries. count=$($syslogMessages.Count)"
        }
    } else {
        Write-Host "No syslog messages produced for this event."
    }
}

Write-Host "Successfully processed $successfullyProcessedCount out of $( $eventHubMessages.Length ) event(s)."

#endregion
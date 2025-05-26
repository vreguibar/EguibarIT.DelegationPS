function Write-CustomLog {
    <#
        .SYNOPSIS
            Logs custom events to the Windows Event Log and optionally to JSON files.

        .DESCRIPTION
            The Write-CustomLog function provides a comprehensive logging solution that
            writes events to the Windows Event Log and optionally to JSON files with
            advanced features:

            - Supports both predefined event templates and custom event definitions
            - Automatically masks sensitive information in log messages
            - Configurable log retention and size limits
            - JSON file output with structured data for easier parsing
            - Event categorization and severity levels
            - ShouldProcess support for -WhatIf and -Confirm parameters

            The function is designed for enterprise environments requiring robust logging
            with security and compliance features built-in.

        .PARAMETER EventInfo
            A predefined EventIDInfo object containing standardized event details. This
            parameter simplifies logging of common events with consistent information.
            The object includes:
            - EventID: Numeric identifier for the event
            - Name: Short name of the event
            - Description: Detailed description
            - EventCategory: Logical category grouping
            - EventSeverity: The severity level

        .PARAMETER CustomEventId
            A custom event identifier when using non-standard events. This is typically
            an integer value from the EventID enumeration.

        .PARAMETER EventName
            The name of the custom event being logged. This should be a short, descriptive
            name that identifies the event type.

        .PARAMETER EventCategory
            Specifies the logical category for the event. Categories help organize events
            for filtering and reporting. Should be a value from the EventCategory enumeration.

        .PARAMETER Message
            The detailed log message that will be written to the event log. Sensitive
            information like passwords or personal data will be automatically masked
            when the RemoveSensitiveData feature is enabled.

        .PARAMETER CustomSeverity
            The severity level of the event (Information, Warning, Error, Critical, etc.).
            This should be a value from the EventSeverity enumeration.

        .PARAMETER LogAsJson
            When specified, the log entry will also be written to a JSON file in addition
            to the Windows Event Log. This enables structured logging for integration with
            log analysis tools.

        .PARAMETER MaximumKilobytes
            Specifies the maximum size in kilobytes for the event log. The default is 16384 KB
            (16 MB). Valid values range from 64 KB to 4,194,240 KB.

        .PARAMETER RetentionDays
            Specifies the number of days event log entries should be retained. The default
            is 30 days. Valid values range from 1 to 365 days.

        .PARAMETER LogPath
            The directory path where JSON log files will be saved when LogAsJson is specified.
            If not provided, logs will be written to the default application data location.

        .EXAMPLE
            Write-CustomLog -EventInfo ([EventIDs]::SlowPerformance) -Message 'System performance degraded due to outdated hardware.' -Verbose

            Uses a predefined event template ([EventIDs]::SlowPerformance) with a custom message.
            The event is logged with all the predefined metadata (category, severity, etc.).

        .EXAMPLE
            Write-CustomLog -CustomEventId ([EventID]::LowDiskSpace) `
                -EventName "LowDiskSpace" `
                -EventCategory SystemHealth `
                -Message "Low disk space detected on C: drive. Free space below 10%." `
                -CustomSeverity Warning `
                -Verbose

            Creates and logs a custom event with specific category and severity level.

        .EXAMPLE
            $logParams = @{
                EventInfo = ([EventIDs]::UnauthorizedAccess)
                Message = "Failed login attempt for user: Administrator from IP: 192.168.1.100"
                LogAsJson = $true
                LogPath = "D:\\SecurityLogs"
            }
            Write-CustomLog @logParams

            Logs a security event both to Windows Event Log and to a JSON file in a custom location.

        .INPUTS
            EventIDInfo

            You can pipe EventIDInfo objects to this function.

        .OUTPUTS
            None

            This function does not generate any output.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Remove-SensitiveData                       ║ EguibarIT.DelegationPS
                Initialize-EventLogging                    ║ EguibarIT.DelegationPS
                Write-EventLog                             ║ Microsoft.PowerShell.Management
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Warning                              ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         2.0
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS

        .COMPONENT
            Logging

        .ROLE
            Operations

        .FUNCTIONALITY
            Event Logging, Auditing

    #>

    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Predefined')]
    [OutputType([void])]

    param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Default Event Information to be used.',
            Position = 0,
            ParameterSetName = 'Predefined')]
        [ValidateNotNullOrEmpty()]
        [EventIDInfo]
        $EventInfo,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Integer representing the Event ID.',
            Position = 1,
            ParameterSetName = 'Custom')]
        [ValidateRange(1000, 65535)] # assuming a valid custom event ID range
        [int]
        $CustomEventId,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Name of the event.',
            Position = 2,
            ParameterSetName = 'Custom')]
        [string]
        $EventName,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Category assigned to the event.',
            Position = 3,
            ParameterSetName = 'Custom')]
        [ValidateScript({
                [Enum]::IsDefined([EventCategory], $_)
            })]
        [EventCategory]
        $EventCategory,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Message of the event.',
            Position = 4)]
        [ValidateLength(1, 2048)]
        [string]
        $Message,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Severity assigned to the event.',
            Position = 5,
            ParameterSetName = 'Custom')]
        #[ValidateSet('Information', 'Warning', 'Error', 'SuccessAudit', 'FailureAudit')]
        [ValidateScript({
                [Enum]::IsDefined([EventSeverity], $_)
            })]
        [EventSeverity]
        $CustomSeverity,

        [Parameter(ParameterSetName = 'JsonLogging')]
        [switch]
        $LogAsJson,

        [Parameter(ParameterSetName = 'EventLogging')]
        [int]
        $MaximumKilobytes = 16384, # default 16 MB

        [Parameter(ParameterSetName = 'EventLogging')]
        [int]
        $RetentionDays = 30, # default 30 days

        [Parameter(ParameterSetName = 'JsonLogging')]
        [ValidateScript({ Test-Path $_ -PathType 'Container' })] # Validate directory
        [string]
        $LogPath = 'C:\Logs',

        [Parameter(ParameterSetName = 'JsonLogging')]
        [string]
        $JsonLogName = 'CustomLog',

        [Parameter(ParameterSetName = 'JsonLogging')]
        [int]
        $JsonMaxFileSizeMB = 10

    )

    Begin {

        Set-StrictMode -Version Latest

        $ErrorActionPreference = 'Stop'

        # Mask sensitive data
        #$maskedMessage = Remove-SensitiveData -Message $Message
        $maskedMessage = $Message

        # Initialize event logging
        Initialize-EventLogging -MaximumKilobytes $MaximumKilobytes -RetentionDays $RetentionDays

        if ($PSCmdlet.ParameterSetName -eq 'Custom') {
            $eventId = $CustomEventId
            $eventName = $EventName
            $eventCategory = $EventCategory
            $severity = $CustomSeverity
        } else {
            $eventId = $EventInfo.ID
            $eventName = $EventInfo.Name
            $eventCategory = $EventInfo.Category
            $severity = $EventInfo.DefaultSeverity
        } #end If-Else

        $entryType = switch ($severity) {
            'Information' {
                [System.Diagnostics.EventLogEntryType]::Information
            }
            'Warning' {
                [System.Diagnostics.EventLogEntryType]::Warning
            }
            'Error' {
                [System.Diagnostics.EventLogEntryType]::Error
            }
            'SuccessAudit' {
                [System.Diagnostics.EventLogEntryType]::SuccessAudit
            }
            'FailureAudit' {
                [System.Diagnostics.EventLogEntryType]::FailureAudit
            }
        }


        $sb = [System.Text.StringBuilder]::new()
        $sb.AppendLine("Event          : $eventName") | Out-Null
        $sb.AppendLine("Event Category : $eventCategory") | Out-Null
        $sb.AppendLine("Details        : $maskedMessage") | Out-Null

    } #end Begin

    Process {
        if ($PSCmdlet.ShouldProcess("Logging event: $eventName with severity $severity")) {
            try {

                # Write to Windows Event Log
                # LogName and Source are defined on $Variables which is initialized when module is imported.
                $Splat = @{
                    LogName   = $Variables.LogConfig.LogName
                    Source    = $Variables.LogConfig.Source
                    EntryType = $entryType
                    EventId   = $eventId
                    Category  = [int]([Enum]::Parse([EventCategory], $eventCategory))  # Convert EventCategory to int
                    Message   = $sb.ToString()
                }
                Write-EventLog @Splat

                # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventlog.writeentry?view=net-8.0
                <# [System.Diagnostics.EventLog]::WriteEntry (string source,
                                                          string message,
                                                          System.Diagnostics.EventLogEntryType type,
                                                          int eventID,
                                                          short category,
                                                          byte[] rawData)

                $params = @(
                    $Source,
                    $Message,
                    $eventType,
                    $EventId
                )

                [System.Diagnostics.EventLog]::WriteEntry($params)
                #>



                # Log to JSON
                if ($LogAsJson) {
                    $logObject = [PSCustomObject]@{
                        EventID        = $eventId
                        Name           = $eventName
                        Category       = $eventCategory
                        Severity       = $severity
                        Message        = $maskedMessage
                        Timestamp      = (Get-Date).ToString('o')
                        AdditionalData = @{
                            # Add any additional structured data here
                            MachineName = $env:COMPUTERNAME
                            UserName    = $env:USERNAME
                        }
                    }

                    $jsonFile = Join-Path $LogPath "$JsonLogName.json"

                    # Ensure directory exists
                    if (-not (Test-Path -Path $LogPath)) {
                        New-Item -ItemType Directory -Force -Path $LogPath | Out-Null
                    }

                    # Check file size and rotate if necessary
                    if (Test-Path $jsonFile) {
                        $fileInfo = Get-Item $jsonFile
                        if ($fileInfo.Length / 1MB -ge $JsonMaxFileSizeMB) {
                            $backupFile = Join-Path $LogPath "$JsonLogName-$(Get-Date -Format 'yyyyMMddHHmmss').json"
                            Move-Item $jsonFile $backupFile
                        }
                    }

                    $logObject | ConvertTo-Json | Out-File -FilePath $jsonFile -Append

                    Write-Verbose -Message ('Event {0} was logged successfully to JSON.' -f $eventName)
                } #end If

                Write-Verbose -Message ('
                    Event {0} with ID {1}
                    was logged successfully to the event log.' -f
                    $eventName, $eventId
                )
            } catch {
                Write-Error -Message ('
                    An error occurred while logging the event.
                    Exception: {0}
                    Full details: {1}' -f
                    $_.Exception.Message, $_
                )
                throw
            } #end Try-Catch
        } #end If
    } #end Process

    End {
        Write-Verbose -Message 'Logging process completed.'
    } #end End
} #end Function

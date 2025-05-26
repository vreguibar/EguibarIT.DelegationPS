function Write-CustomWarning {
    <#
        .SYNOPSIS
            Mimics Write-Warning but with optional logging to the Windows Event Log.

        .DESCRIPTION
            This function writes warning messages to the console and, if instructed, to the specified Windows Event Log.
            It supports both predefined and custom event logging, allowing flexibility in logging approaches.

            The function can be used in two main ways:
            1. With predefined event information using the EventInfo parameter
            2. With custom event details using EventId, EventName, and EventCategory parameters

            When CreateWindowsEvent switch is present, the message will be written both to the console
            and to the Windows Event Log. Otherwise, it will only output to the console as a warning.

        .PARAMETER CreateWindowsEvent
            Switch to indicate if a Windows Event Log entry should be created in addition to outputting a warning message.

        .PARAMETER Message
            The message to be written, either to the console (as a warning) or both to the console and the Windows Event Log.

        .PARAMETER EventInfo
            Predefined event information of type [EventIDs], if using predefined events. These are defined in the
            Class.Events.ps1 file under the Classes folder.

        .PARAMETER EventId
            Custom event ID if logging a custom event. Must be a valid member of the [EventID] enumeration.

        .PARAMETER EventName
            Name of the custom event being logged. Used to identify the event in the Windows Event Log.

        .PARAMETER EventCategory
            Custom event category for the event. Must be a valid member of the [EventCategory] enumeration.

        .EXAMPLE
            Write-CustomWarning -Message "Process failed to start" -Verbose

            Writes a simple warning message to the console with verbose output.

        .EXAMPLE
            Write-CustomWarning -CreateWindowsEvent -EventInfo ([EventIDs]::SlowPerformance) -Message "Old hardware detected."

            Logs a warning message to the console and also creates a Windows Event Log entry using a predefined event info.

        .EXAMPLE
            $Splat = @{
                CreateWindowsEvent = $true
                EventInfo          = ([EventIDs]::GetGroupMembership)
                Message            = 'Fetched all members of the group.'
            }
            Write-CustomWarning @Splat

            Logs a warning message using splatting with a predefined event information.

        .EXAMPLE
            Write-CustomWarning -CreateWindowsEvent -EventId ([EventID]::CustomError) -EventName "CustomEvent" -EventCategory SystemHealth -Message "Custom warning message." -Verbose

            Logs a custom event with specific event details to both the console and the Windows Event Log.

        .INPUTS
            System.String for the Message parameter.

        .OUTPUTS
            System.Void

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Write-CustomLog                            ║ EguibarIT.DelegationPS
                Write-Warning                              ║ Microsoft.PowerShell.Utility

            Ensure necessary event types (EventIDs, EventCategory, etc.) are defined in the Class.Events.ps1 file
            located under Classes folder. This file is written in C# (CSharp) language and compiled at runtime
            when the module is imported. This approach addresses visibility and compatibility issues in PowerShell modules.

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
            System Administration

        .FUNCTIONALITY
            Event Logging, Warning Messages
    #>

    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Default')]
    [OutputType([void])]

    param(

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'If present a new event will be created in the corresponding Windows Event among Write-Verbose.',
            Position = 0)]
        [switch]
        $CreateWindowsEvent,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Message body of the event and/or Verbose message.',
            Position = 1,
            ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Custom')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Message,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Default built-in Event Information to be used of type [EventIDs].',
            Position = 2,
            ParameterSetName = 'Default')]
        [EventIDInfo]
        $EventInfo,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Custom Event ID to be used of type [EventID].',
            Position = 2,
            ParameterSetName = 'Custom')]
        [ValidateScript({
                [Enum]::IsDefined([EventID], $_)
            })]
        [EventID]
        $EventId,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Custom Event Name to be used.',
            Position = 3,
            ParameterSetName = 'Custom')]
        [ValidateNotNullOrEmpty()]
        [string]
        $EventName,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Custom Category to be used of type [EventCategory].',
            Position = 4,
            ParameterSetName = 'Custom')]
        [ValidateScript({
                [Enum]::IsDefined([EventCategory], $_)
            })]
        [EventCategory]
        $EventCategory

    )

    Begin {

        Set-StrictMode -Version Latest

        $ErrorActionPreference = 'Stop'

        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

    } #end Begin

    Process {
        if ($PSCmdlet.ShouldProcess("Writing verbose log: $Message")) {

            # Handle logging to Windows Event Log if requested
            If ($PSBoundParameters.ContainsKey('CreateWindowsEvent')) {

                # Use predefined event info if available, otherwise, use custom event details
                If ($PSBoundParameters.ContainsKey('EventInfo')) {

                    # Predefined (Built-In) event to be used.
                    # Those are defined on the Class.Events.ps1 file under Classes folder.
                    Write-CustomLog -EventInfo $PSBoundParameters['EventInfo'] -Message $PSBoundParameters['Message']

                } else {

                    # Custom event logging
                    $Splat = @{
                        CustomEventId  = $PSBoundParameters['EventID']
                        EventName      = $PSBoundParameters['EventName']
                        EventCategory  = $PSBoundParameters['EventCategory']
                        Message        = $PSBoundParameters['Message']
                        CustomSeverity = [EventSeverity]::Warning
                        Verbose        = $PSBoundParameters['Verbose']
                    }
                    Write-CustomLog @Splat

                } #end Else-If

            } #end If CreateWindowsEvent

            # Call Write-Verbose with parsed message.
            Write-Warning -Message $Message -Verbose:$PSBoundParameters['Verbose']
        }
    } #end Process

    End {

    } #end End
} #end Function

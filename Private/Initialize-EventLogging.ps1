function Initialize-EventLogging {

    <#
        .SYNOPSIS
            Initializes event logging by creating and configuring a new event log.

        .DESCRIPTION
            This function initializes and configures the event logging system for the EguibarIT.DelegationPS module.
            It performs the following operations:

            - Checks if the specified event log source exists
            - Creates the log source if it doesn't exist
            - Configures the maximum size of the event log
            - Sets the retention period for event log entries
            - Implements error-handling with retry logic for robustness
            - Supports ShouldProcess for -WhatIf and -Confirm parameters

            The function is typically called during module initialization but can also be
            called manually to reconfigure logging parameters.

        .PARAMETER MaximumKilobytes
            Specifies the maximum size of the event log in kilobytes. Default is 16384 KB (16 MB).
            The valid range is from 64 KB to 1048576 KB (1 GB).

        .PARAMETER RetentionDays
            Specifies the number of days to retain event log entries. Default is 30 days.
            The valid range is from 1 to 365 days (1 year).

        .EXAMPLE
            Initialize-EventLogging -MaximumKilobytes 8192 -RetentionDays 15 -Verbose

            Initializes event logging with a log size of 8192 KB (8 MB) and retention period of 15 days,
            with verbose output enabled to show detailed progress information.

        .EXAMPLE
            Initialize-EventLogging -WhatIf

            Shows what would happen if the event logging were initialized, without making any changes.
            Useful for checking what the function would do without actually modifying the system.

        .INPUTS
            System.Int32

            You can pipe integer values to the MaximumKilobytes and RetentionDays parameters.

        .OUTPUTS
            System.Void

            This function does not generate any output. It creates or modifies Windows event logs
            and writes to the verbose stream or throws an error if initialization fails.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Get-FunctionDisplay                        ║ EguibarIT.DelegationPS
                Get-Date                                   ║ Microsoft.PowerShell.Utility
                Limit-EventLog                             ║ Microsoft.PowerShell.Management
                Write-EventLog                             ║ Microsoft.PowerShell.Management
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Warning                              ║ Microsoft.PowerShell.Utility
                New-EventLog                               ║ Microsoft.PowerShell.Management

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
            EguibarIT.DelegationPS

        .ROLE
            Infrastructure

        .FUNCTIONALITY
            Event Logging
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([void])]

    param (
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Maximum size of the Event file.',
            Position = 0)]
        [ValidateRange(64, 1048576)]  # Minimum of 64 KB, max of 1 GB
        [PSDefaultValue(Help = 'Default Value is "16384"')]
        [int]
        $MaximumKilobytes = 16384, # default to 16 MB

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Maximum day to retain events.',
            Position = 0)]
        [ValidateRange(1, 365)]  # Minimum of 1 day, max of 1 year
        [PSDefaultValue(Help = 'Default Value is "30"')]
        [int]
        $RetentionDays = 30         # default to 30 days
    )

    Begin {

        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and $null -ne $Variables.HeaderDelegation) {
            $txt = ($Variables.HeaderDelegation -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.MyCommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$false)
            )
            Write-Verbose -Message $txt
        } #end if

        ##############################
        # Variables Definition

        # parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Retry logic in case of failure
        $retryCount = 0
        $lastError = $null

    } #end Begin

    Process {
        # Retry logic with up to 3 attempts
        if (-not $Variables.EventLogInitialized) {
            try {
                # Check if the event source exists, and if not, create it
                if (-not [System.Diagnostics.EventLog]::SourceExists($Variables.LogConfig.Source)) {

                    if ($PSCmdlet.ShouldProcess("Event log source $($Variables.LogConfig.Source)", 'Create event log')) {
                        $Splat = @{
                            LogName = $Variables.LogConfig.LogName
                            Source  = $Variables.LogConfig.Source
                            Verbose = ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose') -and
                                $PSCmdlet.MyInvocation.BoundParameters['Verbose'] -eq $true)
                        }
                        New-EventLog @Splat

                        Write-Verbose -Message ('Log {0} did not exist. It got created.' -f $Variables.LogConfig.LogName)

                        $Splat = @{
                            LogName        = $Variables.LogConfig.LogName
                            MaximumSize    = $MaximumKilobytes * 1KB
                            OverflowAction = 'OverwriteOlder'
                            RetentionDays  = $RetentionDays
                            Verbose        = ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose') -and
                                $PSCmdlet.MyInvocation.BoundParameters['Verbose'] -eq $true)
                        }
                        Limit-EventLog @Splat

                        Write-Verbose -Message ('Log {0} was configured correctly.' -f $Variables.LogConfig.LogName)
                    } #end If ShouldProcess

                } #end If SourceExist

                # Set Global Variable
                $Variables.EventLogInitialized = $true

            } catch {
                $lastError = $_
                $retryCount++

                Write-Warning -Message ('Failed to initialize event logging (Attempt {0}/3). Error: {1}' -f
                    $retryCount, $_.Exception.Message)

                Start-Sleep -Seconds 2
            } #end Try-Catch

        } #end While

        if (-not $Variables.EventLogInitialized) {
            $errorDetails = if ($null -ne $lastError) {
                'Last error: {0}. Exception type: {1}' -f $lastError.Exception.Message, $lastError.Exception.GetType().FullName
            } else {
                'No specific error was captured during the retry attempts.'
            }

            $errorMessage = @(
                'Failed to initialize event log after 3 attempts.',
                $errorDetails,
                'Verify that:',
                '  1. The current user has permission to create event logs',
                '  2. The LogConfig.Source and LogConfig.LogName variables are properly initialized',
                '  3. The event log service is running'
            ) -join [Environment]::NewLine

            throw $errorMessage
        } #end If

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'initializing Event Logging. (Private Function)'
        )
        Write-Verbose -Message $txt
    } #end End
} #end Function

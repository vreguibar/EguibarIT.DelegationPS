Function Get-AdWellKnownSID {
    <#
        .Synopsis
            Checks if the provided SID is a Well-Known SID.

        .Description
            This function verifies if the provided Security Identifier (SID) is a Well-Known SID.
            It returns $True if it is a Well-Known SID or $False otherwise.

        .EXAMPLE
            Get-AdWellKnownSID -SID 'S-1-5-18'
            True
            This command checks if the SID for the Local System Account ('S-1-5-18') is a Well-Known SID.

        .Parameter SID
            The Security IDentifier (SID) to check.

        .NOTES
            Version:         2.0
            DateModified:    8/Feb/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Medium')]
    [OutputType([Bool])]

    Param (

        [Parameter(Mandatory = $true, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (Security IDentifier or SID) to check if it IS a WellKnownSID.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        $SID
    )

    Begin {

        $error.clear()

        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        $isWellKnownSid = $false
        $sidDescription = ''

        # $WellKnownSids variable is defined on .\Enums\Enum.WellKnownSids.ps1
        # Check is populated, otherwise fill it up
        If ( ($null -eq $Variables.WellKnownSIDs) -or
            (0 -eq $Variables.WellKnownSIDs) -or
            ('' -eq $Variables.WellKnownSIDs) -or
            ($Variables.WellKnownSIDs.length -eq 0) -or
            ($Variables.WellKnownSIDs -eq $false)
        ) {
            .\Enums\Enum.WellKnownSids.ps1
        }

    } # end Begin

    Process {

        try {

            # Assuming $WellKnownSIDs is a hashtable where keys are the well-known SID values
            if ($WellKnownSIDs.Contains($sid)) {
                $isWellKnownSid = $true
                $sidDescription = $WellKnownSIDs[$SID]
            }

            Write-Verbose "  Checked SID: $SID."
            Write-Verbose "Is Well-Known: $isWellKnownSid"
            Write-Verbose "  Description: $sidDescription"
        } catch {
            Get-CurrentErrorToDisplay -CurrentError $error[0]
        } #end Try-Catch

    } # end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished checking for Well-Known SIDs."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''

        return $IsWellKnownSid
    } #end End
} # End Function

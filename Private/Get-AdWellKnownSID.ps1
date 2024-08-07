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
        [ValidateScript({ Test-IsValidSID -ObjectSID $_ })]
        [ValidateNotNullOrEmpty()]
        $SID
    )

    Begin {
        If($PSBoundParameters) {
            $Display = Get-FunctionDisplay $PsBoundParameters -Verbose:$False
        } else {
            $Display =
        }
        $txt = ($constants.Header -f (Get-Date).ToShortDateString(), $MyInvocation.Mycommand, (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        $isWellKnownSid = $false
        $sidDescription = ''

        # $WellKnownSids variable is defined on .\Enums\Enum.WellKnownSids.ps1
        # Check is populated, otherwise fill it up
        If ( (-not $Variables.WellKnownSIDs) -or
            ($Variables.WellKnownSIDs.Count -eq 0) -or
            ($Variables.WellKnownSIDs -eq 0) -or
            ($Variables.WellKnownSIDs -eq '') -or
            ($Variables.WellKnownSIDs -eq $false)
        ) {
            . "$PSScriptRoot\Enums\Enum.WellKnownSids.ps1"
        }

    } # end Begin

    Process {

        try {

            # Assuming $WellKnownSIDs is a hashtable where keys are the well-known SID values
            if ($Variables.WellKnownSIDs.ContainsKey($SID)) {
                $isWellKnownSid = $true
                $sidDescription = $Variables.WellKnownSIDs[$SID]
            }

            Write-Verbose -Message ('  Checked SID: {0}.' -f $SID)
            Write-Verbose -Message ('Is Well-Known: {0}' -f $isWellKnownSid)
            Write-Verbose -Message ('  Description: {0}' -f $sidDescription)
        } catch {
            Write-Error -Message 'Error when checking WellKnownSid'
            throw
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

Function Get-AdWellKnownSID {
    <#
        .SYNOPSIS
            Checks if the provided SID is a Well-Known SID.

        .DESCRIPTION
            This function verifies if the provided Security Identifier (SID) is a Well-Known SID.
            It returns $True if it is a Well-Known SID or $False otherwise. The function can
            process multiple SIDs in a single execution via the pipeline.

        .EXAMPLE
            Get-AdWellKnownSID -SID 'S-1-5-18'

            Returns True because 'S-1-5-18' (Local System Account) is a Well-Known SID.

        .EXAMPLE
            'S-1-5-18', 'S-1-5-19', 'S-1-5-20' | Get-AdWellKnownSID

            Returns True for each SID as all three are Well-Known SIDs.

        .EXAMPLE
            Get-AdWellKnownSID -SID 'S-1-5-18' -Detailed

            Returns a custom object containing:
            - SID: The original SID
            - IsWellKnown: True
            - Description: "Local System Account"

        .PARAMETER SID
            The Security IDentifier (SID) to check. Accepts multiple SIDs via pipeline.

        .PARAMETER Detailed
            When specified, returns a detailed object including the SID description.

        .OUTPUTS
            [Bool] or [PSCustomObject]

            When -Detailed is not specified, returns $True if the SID is a Well-Known SID or $False otherwise.
            When -Detailed is specified, returns a custom object with properties: SID, IsWellKnown, and Description.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Warning                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                        ║ EguibarIT
                Test-IsValidSID                            ║ EguibarIT.DelegationPS

        .NOTES
            Version:         2.1
            DateModified:    20/Mar/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Private/Get-AdWellKnownSID.ps1
    #>

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Medium')]
    [OutputType([Bool])]

    Param (

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity (Security IDentifier or SID) to check if it IS a WellKnownSID.',
            Position = 0)]
        [ValidateScript(
            { Test-IsValidSID -ObjectSID $_ },
            ErrorMessage = 'Provided SID is not valid! Please check.'
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('SecurityIdentifier', 'ObjectSID')]
        $SID
    )

    Begin {

        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and $null -ne $Variables.HeaderDelegation) {
            $txt = ($Variables.HeaderDelegation -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end if

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        [bool]$isWellKnownSid = $false
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
        } #end If

    } # end Begin

    Process {

        try {

            # Assuming $WellKnownSIDs is a hashtable where keys are the well-known SID values
            if ($Variables.WellKnownSIDs.ContainsKey($SID)) {

                $isWellKnownSid = $true
                $sidDescription = $Variables.WellKnownSIDs[$SID]

                Write-Verbose -Message ('
                  Checked SID: {0}.
                Is Well-Known: {0}
                  Description: {0}' -f $SID, $isWellKnownSid, $sidDescription
                )
            } #end if

        } catch {

            Write-Error -Message 'Error when checking WellKnownSid'
            throw

        } #end Try-Catch

    } # end Process

    End {
        if ($null -ne $Variables -and $null -ne $Variables.FooterDelegation) {
            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'checking for Well-Known SIDs (Private Function).'
            )
            Write-Verbose -Message $txt
        } #end if

        return $IsWellKnownSid
    } #end End

} # End Function Get-AdWellKnownSID

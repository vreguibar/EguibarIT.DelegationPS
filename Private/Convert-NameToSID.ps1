﻿function Convert-NameToSID {
    <#
        .SYNOPSIS
            Converts an account name to a Security Identifier (SID).

        .DESCRIPTION
            This function takes an account name (e.g., domain\username) and converts it to
            its corresponding Security Identifier (SID).

        .PARAMETER AccountName
            The account name to be converted to a SID. This should be in the format
            domain\username or just username for local accounts.

        .EXAMPLE
            Convert-NameToSID -AccountName "EguibarIT\davade"
            'S-1-5-21-3623811015-3361044348-30300820-1013'

        .INPUTS
            [string] - Account name.

        .OUTPUTS
            [System.Security.Principal.SecurityIdentifier] - The SID corresponding to the account name.
    #>

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]
    [OutputType([System.Security.Principal.SecurityIdentifier])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Enter the account name in the format domain\username or username.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        $AccountName
    )

    Begin {

        Set-StrictMode -Version Latest

        $txt = ($Variables.HeaderDelegation -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        $AccountName = Get-AdObjectType -Identity $PSBoundParameters['AccountName']

    } #end Begin

    Process {
        try {

            Write-Verbose -Message ('Converting {0} to SID.' -f $AccountName)

            If ($AccountName) {

                return [System.Security.Principal.SecurityIdentifier]::new($AccountName.SID.Value)

                Write-Verbose -Message ('Successfully converted {0} to SID: {1}.' -f $AccountName, $sid)
            } # end If
        } catch {
            Write-Error -Message ('Failed to convert {0} to SID. Error: {1}' -f $AccountName, $_.Exception.Message)
            #Get-ErrorDetail -ErrorRecord $_
            return $null
        } #end Try-Catch
    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'converting account name to SID (Private Function).'
        )
        Write-Verbose -Message $txt
    } #end End
}

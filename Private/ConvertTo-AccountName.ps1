function ConvertTo-AccountName {
    <#
        .SYNOPSIS
            Converts a Security Identifier (SID) to an account name.

        .DESCRIPTION
            This function takes a Security Identifier (SID) as input and translates it to the corresponding NT account name.
            It uses the System.Security.Principal.SecurityIdentifier class to perform the translation.

        .PARAMETER SID
            The Security Identifier (SID) to be converted to an account name.

        .EXAMPLE
            PS> ConvertTo-AccountName -SID "S-1-5-21-3623811015-3361044348-30300820-1013"
            EguibarIT\davade

        .INPUTS
            [string] - The SID that you want to convert to an account name.

        .OUTPUTS
            [System.Security.Principal.NTAccount] - The NT account name corresponding to the given SID.
    #>

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]
    [OutputType([System.Security.Principal.NTAccount])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Enter the Security Identifier (SID) to be converted to an account name.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            { Test-IsValidSID -ObjectSID $_ },
            ErrorMessage = 'The SID provided {0} is not valid. Please check the provided value.'
        )]
        [string]
        $SID
    )

    Begin {
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

    } #end Begin

    Process {


        try {
            Write-Verbose -Message ('Attempting to convert SID: {0} to account name' -f $PSBoundParameters['SID'])

            # Check if the SID exists in the Well-Known SIDs hashtable
            if ($Variables.WellKnownSIDs.Keys.Contains($PSBoundParameters['SID'])) {

                Write-Verbose -Message ('
                    SID {0} found on the Well-Known SIDs table.
                    Returning cached account name.' -f
                    $PSBoundParameters['SID']
                )
                return [System.Security.Principal.NTAccount]::new($Variables.WellKnownSIDs[$PSBoundParameters['SID']])

            } else {

                # Create a SecurityIdentifier object from the SID string
                $tmpSid = [System.Security.Principal.SecurityIdentifier]::New($PSBoundParameters['SID'])

                # Return Translated SID to an NTAccount object
                return $tmpSid.Translate([System.Security.Principal.NTAccount])

            } #end If-Else

        } catch {
            Write-Warning -Message ('
                Failed to convert SID: {0}
                to account name.
                {1}
                This account should not be processed further.' -f
                $PSBoundParameters['SID'], $_
            )
            return $null
        } #end Try-Catch

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'translating SID to account name (Private Function).'
        )
        Write-Verbose -Message $txt
    } #end End
}

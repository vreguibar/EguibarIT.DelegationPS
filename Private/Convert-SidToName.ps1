Function Convert-SidToName {
    <#
        .SYNOPSIS
            Converts a Security Identifier (SID) to its corresponding NT Account Name.

        .DESCRIPTION
            This function translates a given Security Identifier (SID) to the corresponding
            NT Account Name using .NET classes. It is useful for converting SIDs to a more
            human-readable form.

        .PARAMETER SID
            The Security Identifier (SID) to be translated to an NT Account Name.
            The SID must be a valid string representation of a SID.

        .EXAMPLE
            Convert-SidToName -SID 'S-1-5-21-3623811015-3361044348-30300820-1013'
            EguibarIT\davade

        .INPUTS
            [string] The function accepts a string input representing the SID.

        .OUTPUTS
            [string] The function outputs a string representing the NT Account Name.

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-ADRootDSE                          | ActiveDirectory
                Get-ADObject                           | ActiveDirectory

            Version:         1.1
            DateModified:    14/Mar/2024
            LastModifiedBy:  Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([bool])]

    param (
        # PARAM1 STRING representing the GUID
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'SID of the object to be translated',
            Position = 0)]
        [ValidateScript(
            { Test-IsValidSID -ObjectSID $_ },
            ErrorMessage = '[PARAMETER] Provided SID is not valid! Function will not continue. Please check.'
        )]
        [ValidateNotNullOrEmpty()]
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
        $FoundName = $null

    } #end Begin

    Process {

        # Check Well-Known SIDs first
        if ($Variables.WellKnownSIDs.Keys.ContainsKey($PSBoundParameters['SID'])) {

            Write-Verbose -Message ('
                Resolved SID {0}
                from Well-Known SIDs: {1}' -f
                $Sid, $Variables.WellKnownSIDs[$PSBoundParameters['SID']]
            )
            return $Variables.WellKnownSIDs[$Sid]

        } #end If

        # Fallback to dynamic resolution
        try {

            # Attempt to translate the SID to a name
            $SecurityIdentifier = [Security.Principal.SecurityIdentifier]::New($PSBoundParameters['SID'])

            # Get the account name based on SID
            $FoundName = ($SecurityIdentifier.Translate([Security.Principal.NTAccount])).Value

            Write-Verbose -Message ('
                Converted SID {0}
                to account name: {1}' -f
                $Sid, $objUser.Value
            )

        } catch [System.Security.Principal.IdentityNotMappedException] {

            Write-Warning 'Identity Not Mapped Exception. The SID could not be translated to an account name.'
            $FoundName = $null

        } catch {
            Write-Error -Message ('
                An unexpected error occurred while converting SID
                SID: {0}
                {1}' -f
                $PSBoundParameters['SID'], $_
            )

            $FoundName = $null
        }#end Try-Catch

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'translating SID to Name (Private Function).'
        )
        Write-Verbose -Message $txt

        return $FoundName
    } #end End
}

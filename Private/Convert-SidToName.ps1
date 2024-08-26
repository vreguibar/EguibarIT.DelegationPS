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
            PS> Convert-SidToName -SID 'S-1-5-21-3623811015-3361044348-30300820-1013'
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
        [ValidateScript({ Test-IsValidSID -ObjectSID $_ })]
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

        try {

            # Attempt to translate the SID to a name
            $SecurityIdentifier = [Security.Principal.SecurityIdentifier]::New($PSBoundParameters['SID'])

            # Get the account name based on SID
            $FoundName = ($SecurityIdentifier.Translate([Security.Principal.NTAccount])).Value

        } catch [System.Security.Principal.IdentityNotMappedException] {

            Write-Warning 'Identity Not Mapped Exception'
            $FoundName = $null

        } catch {
            Write-Error -Message ('An unexpected error occurred: {0}' -f $_)
            $FoundName = $null
            throw
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

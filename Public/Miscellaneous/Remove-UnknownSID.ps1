Function Remove-UnknownSID {
    <#
        .Synopsis
            Remove Un-Resolvable SID from a given object
        .DESCRIPTION
            Remove Un-Resolvable SID from a given object. If a SID is displayed within the ACE, is
            because a name could not be resolved. Most likely the object was deleted, and its friendly
            name could not be retrived. This function will identify this unresolved SID and remove it from the ACE
        .EXAMPLE
            Remove-UnknownSID -LDAPpath "OU=Users,OU=Good,OU=Sites,DC=EguibarIT,DC=local"
        .EXAMPLE
            Remove-UnknownSID -LDAPpath "OU=Users,OU=Good,OU=Sites,DC=EguibarIT,DC=local" -RemoveSID
        .PARAMETER LDAPpath
            [String] Distinguished Name of the object (or container) where the Unknown SID is located
        .PARAMETER RemoveSID
            Switch indicator to remove the unknown SID
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
        .NOTES
            Version:         1.0
            DateModified:    21/Sep/2022
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Medium')]

    Param (
        # PARAM1 STRING for the Object Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the object (or container) where the Unknown SID is located.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPpath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Switch indicator to remove the unknown SID.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [switch]
        $RemoveSID
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

    } # end Begin

    Process {

    } # end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating central OU."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}

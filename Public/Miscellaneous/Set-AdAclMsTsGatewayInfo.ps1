# Read and write MS-TS Info -  MS-TS-GatewayAccess property set - http://msdn.microsoft.com/en-us/library/ms684392(v=vs.85).aspx
function Set-AdAclMsTsGatewayInfo {
    <#
        .Synopsis
            The function will delegate the premission for a group to read/write
            MS TerminalServices Gateway Information Computer objects in an OU
        .DESCRIPTION
            The function will delegate the premission for a group to read/write
            MS TerminalServices Gateway Information Computer objects in an OU
        .EXAMPLE
            Set-AdAclMsTsGatewayInfo -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .EXAMPLE
            Set-AdAclMsTsGatewayInfo -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .PARAMETER Group
            [STRING] for the Delegated Group Name
        .PARAMETER LDAPpath
            [STRING] Distinguished Name of the OU where the computer DnsInfo will be set.
        .PARAMETER RemoveRule
            Param3 RemoveRule:...[SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor6                    | EguibarIT.Delegation
                New-GuidObjectHashTable                | EguibarIT.Delegation
                New-ExtenderRightHashTable             | EguibarIT.Delegation
        .NOTES
            Version:         1.1
            DateModified:    14/Oct/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Group,

        # PARAM2 Distinguished Name of the OU where the computer DnsInfo will be set
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where the computer DnsInfo will be set',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPpath,

        # PARAM3 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        $guidmap           = New-GuidObjectHashTable
        $extendedrightsmap = New-ExtenderRightHashTable
        $parameters        = $null
    } #end Begin

    Process {
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'ReadProperty, WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $extendedrightsmap['MS-TS-GatewayAccess']
            InheritedObjectType   = $guidmap['computer']
            AdSecurityInheritance = 'Descendents'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor6 @parameters
    }

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}

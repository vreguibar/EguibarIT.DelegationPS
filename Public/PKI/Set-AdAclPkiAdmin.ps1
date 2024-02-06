function Set-AdAclPkiAdmin {
    <#
        .Synopsis
            The function will delegate full control premission for a group
            over Certificate Authority
        .DESCRIPTION
            Configures the configuration container to delegate the permissions to a group
            so it can fully manage Certificate Authority (CA or PKI).
        .EXAMPLE
            Set-AdAclPkiAdmin -Group "SG_PkiAdmin" -ItRightsOuDN "OU=Rights,OU=Admin,DC=EguibarIT,DC=local"
        .EXAMPLE
            Set-AdAclPkiAdmin -Group "SG_PkiAdmin" -ItRightsOuDN "OU=Rights,OU=Admin,DC=EguibarIT,DC=local" -RemoveRule
        .PARAMETER Group
            [STRING] for the Delegated Group Name
        .PARAMETER ItRightsOuDN
            [STRING] Distinguished Name of the OU having the Rights groups, where the "Cert Publishers" built-in group resides (Usually OU=Rights,OU=Admin,DC=EguibarIT,DC=local).
        .PARAMETER RemoveRule
            [SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor5                    | EguibarIT.Delegation
        .NOTES
            Version:         1.1
            DateModified:    17/Oct/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]

    param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Group Name which will get the delegation',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Group,

        #PARAM2 Distinguished Name of the OU were the groups can be changed
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU having the Rights groups, where the "Cert Publishers" built-in group resides (Usually OU=Rights,OU=Admin,DC=EguibarIT,DC=local).',
        Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ItRightsOuDN,

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
        $parameters = $null
    } #end Begin

    Process {
        <#
            ACENumber             : 3
            IdentityReference     : EguibarIT\XXXX
            AdRight               : GenericAll
            AccessControlType     : Allow
            ObjectType            : All [nullGUID]
            AdSecurityInheritance : All
            InheritedObjectType   : All [nullGUID]
            IsInherited           : False
        #>
        # Certificate Authority Admin
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Public Key Services,CN=Services,{0}' -f $Variables.configurationNamingContext
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'All'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters

        <#
            ACENumber             : 1
            IdentityReference     : EguibarIT\XXX
            AdRight               : ListChildren, ReadProperty, GenericWrite
            AccessControlType     : Allow
            ObjectType            : All [nullGUID]
            AdSecurityInheritance : None
            InheritedObjectType   : All [nullGUID]
            IsInherited           : False
        #>
        # rights to modify security permissions for Pre-Windows 2000 Compatible Access group.
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Pre-Windows 2000 Compatible Access,CN=Builtin,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'ListChildren', 'ReadProperty', 'GenericWrite'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'None'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters

        <#
            ACENumber             : 2
            IdentityReference     : EguibarIT\XXX
            AdRight               : ListChildren, ReadProperty, GenericWrite
            AccessControlType     : Allow
            ObjectType            : All [nullGUID]
            AdSecurityInheritance : None
            InheritedObjectType   : All [nullGUID]
            IsInherited           : False
        #>
        # rights to modify security permissions for Cert Publishers group.
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Cert Publishers,{0}' -f $PSBoundParameters['ItRightsOuDN']
            AdRight               = 'ListChildren', 'ReadProperty', 'GenericWrite'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'None'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters
    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}

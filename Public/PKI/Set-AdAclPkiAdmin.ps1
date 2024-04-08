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
    [OutputType([void])]

    param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Group Name which will get the delegation',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        $Group,

        #PARAM2 Distinguished Name of the OU were the groups can be changed
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU having the Rights groups, where the "Cert Publishers" built-in group resides (Usually OU=Rights,OU=Admin,DC=EguibarIT,DC=local).',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ })]
        [Alias('DN', 'DistinguishedName')]
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
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New()

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

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
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = 'CN=Public Key Services,CN=Services,{0}' -f $Variables.configurationNamingContext
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'All'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for PKI?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for PKI?')) {
            Set-AclConstructor5 @Splat
        } #end If

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
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = 'CN=Pre-Windows 2000 Compatible Access,CN=Builtin,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'ListChildren', 'ReadProperty', 'GenericWrite'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'None'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for PKI?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for PKI?')) {
            Set-AclConstructor5 @Splat
        } #end If

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
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = 'CN=Cert Publishers,{0}' -f $PSBoundParameters['ItRightsOuDN']
            AdRight               = 'ListChildren', 'ReadProperty', 'GenericWrite'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'None'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for PKI?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for PKI?')) {
            Set-AclConstructor5 @Splat
        } #end If

    } #end Process

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0}' -f $PSBoundParameters['Group'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0}' -f $PSBoundParameters['Group'])
        } #end If-Else

        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating management of PKI."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}

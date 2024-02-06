function Set-AdAclCreateDeleteSite {
    <#
        .Synopsis
            The function will delegate the premission for a group to
            Create and Delete Sites
        .DESCRIPTION
            Long description
        .EXAMPLE
            Set-AdAclCreateDeleteSite -Group "SG_SiteAdmins_XXXX"
        .EXAMPLE
            Set-AdAclCreateDeleteSite -Group "SG_SiteAdmins_XXXX" -RemoveRule
        .PARAMETER Group
            [STRING] for the Delegated Group Name
        .PARAMETER RemoveRule
            [SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor4                    | EguibarIT.Delegation
                Set-AclConstructor5                    | EguibarIT.Delegation
                Set-AclConstructor6                    | EguibarIT.Delegation
                New-GuidObjectHashTable                | EguibarIT.Delegation
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
        [Alias('IdentityReference','Identity','Trustee','GroupID')]
        [String]
        $Group,

        # PARAM2 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
    )
    begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
        $parameters     = $null

        If ( ($null -eq $Variables.GuidMap) -and
                 ($Variables.GuidMap -ne 0)     -and
                 ($Variables.GuidMap -ne '')    -and
                 (   ($Variables.GuidMap -isnot [array]) -or
                     ($Variables.GuidMap.Length -ne 0)) -and
                 ($Variables.GuidMap -ne $false)
            ) {
            # $Variables.GuidMap is empty. Call function to fill it up
            Write-Verbose -Message 'Variable $Variables.GuidMap is empty. Calling function to fill it up.'
            New-GuidObjectHashTable
        }
    } #end Begin
    process {
        <#
            ACE number: 1
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : GuidNULL
                    InheritanceType : Descendents
                InheritedObjectType : site [ClassSchema]
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext.ToString()
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['site']
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor6 @parameters

        <#
            ACE number: 2
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : site [ClassSchema]
                    InheritanceType : All
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext.ToString()
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['site']
            AdSecurityInheritance = 'All'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters

        <#
            ACE number: 3
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : nTDSSiteSettings [ClassSchema]
                    InheritanceType : Descendents
                InheritedObjectType : site [ClassSchema]
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext.ToString()
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['nTDSSiteSettings']
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['site']
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor6 @parameters

        <#
            ACE number: 4
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : nTDSDSA [ClassSchema]
                    InheritanceType : Descendents
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext.ToString()
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['nTDSDSA']
            AdSecurityInheritance = 'Descendents'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters


        <#
            ACE number: 5
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : WriteDacl
                  AccessControlType : Allow
                         ObjectType : nTDSDSA [ClassSchema]
                    InheritanceType : Descendents
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext.ToString()
            AdRight               = 'WriteDacl'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['nTDSDSA']
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor4 @parameters

        <#
            ACE number: 6
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : server [ClassSchema]
                    InheritanceType : Descendents
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext.ToString()
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['server']
            AdSecurityInheritance = 'Descendents'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters

        <#

            ACE number: 7
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : nTDSConnection [ClassSchema]
                    InheritanceType : Descendents
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext.ToString()
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['nTDSConnection']
            AdSecurityInheritance = 'Descendents'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters

        <#
            ACE number: 8
            --------------------------------------------------------
                 IdentityReference : XXX
            ActiveDirectoryRightst : GenericAll
            AccessControlType      : Allow
            ObjectType             : GuidNULL
            InheritanceType        : Descendents
            InheritedObjectType    : serversContainer [ClassSchema]
            IsInherited            = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext.ToString()
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            InheritedObjectType   = $Variables.GuidMap['serversContainer']
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'Descendents'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor6 @parameters

        <#
            ACE number: 9
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : GenericAll
             AccessControlType      : Allow
             ObjectType             : GuidNULL
             InheritanceType        : Descendents
             InheritedObjectType    : msDNS-ServerSettings [ClassSchema]
             IsInherited            = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext.ToString()
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            InheritedObjectType   = $Variables.GuidMap['msDNS-ServerSettings']
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'Descendents'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor6 @parameters


    } #end Process
    end {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
}

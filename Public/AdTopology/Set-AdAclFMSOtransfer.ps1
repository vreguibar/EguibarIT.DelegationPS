Function Set-AdAclFMSOtransfer {
    <#
        .Synopsis
            Delegate the management rights of FMSO roles
        .DESCRIPTION
            Delegate the right to transfer any of the 5 FMSO roles to a given group
        .EXAMPLE
            Set-AdAclFMSOtransfer -Group "SL_FSMOadmin" -FSMOroles 'Schema', 'Infrastructure', 'DomainNaming', 'RID', 'PDC'
        .EXAMPLE
            Set-AdAclFMSOtransfer -Group "SL_FSMOadmin" -FSMOroles 'Schema', 'Infrastructure', 'DomainNaming', 'RID', 'PDC' -RemoveRule
        .PARAMETER Group
            [STRING] Identity of the group getting the delegation
        .PARAMETER FSMOroles
            [String[]] Flexible Single Master Operations (FSMO) Roles to delegate. Only accepted values are Schema, Infrastructure, DomainNaming, RID, PDC
        .PARAMETER RemoveRule
            [Switch] If present, the access rule will be removed.
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor4                    | EguibarIT.Delegation
                New-GuidObjectHashTable                | EguibarIT.Delegation
                New-ExtenderRightHashTable             | EguibarIT.Delegation
        .NOTES
            Version:         1.0
            DateModified:    26/Apr/2022
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Low')]

    Param (

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference','Identity','Trustee','GroupID')]
        [String]
        $Group,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Flexible Single Master Operations (FSMO) Roles to delegate.',
            Position = 1)]
        [ValidateSet('Schema', 'Infrastructure', 'DomainNaming', 'RID', 'PDC')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $FSMOroles,

        # PARAM3 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 2)]
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

        If ( ($null -eq $Variables.ExtendedRightsMap) -and
                 ($Variables.ExtendedRightsMap -ne 0)     -and
                 ($Variables.ExtendedRightsMap -ne '')    -and
                 (   ($Variables.ExtendedRightsMap -isnot [array]) -or
                     ($Variables.ExtendedRightsMap.Length -ne 0)) -and
                 ($Variables.ExtendedRightsMap -ne $false)
            ) {
            # $Variables.ExtendedRightsMap is empty. Call function to fill it up
            Write-Verbose -Message 'Variable $Variables.ExtendedRightsMap is empty. Calling function to fill it up.'
            New-ExtenderRightHashTable
        }
    } #end Begin

    Process {
        # Process each of the FMSO roles
        foreach($Role in $FSMOroles) {
            switch($role){
                # Forest wide roles
                'Schema' {
                    <#
                        Get-AclAccessRule -LDAPpath 'CN=Schema,CN=Configuration,DC=EguibarIT,DC=local' -SearchBy xxxx

                        ACENumber              : 1
                        DistinguishedName      : CN=Schema,CN=Configuration,DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRightst : ExtendedRight
                        AccessControlType      : Allow
                        ObjectType             : Change Schema Master [Extended Rights]
                        InheritanceType        : None
                        InheritedObjectType    : GuidNULL
                        IsInherited            : False

                        ACENumber              : 2
                        DistinguishedName      : CN=Schema,CN=Configuration,DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRightst : WriteProperty
                        AccessControlType      : Allow
                        ObjectType             : fSMORoleOwner [AttributeSchema]
                        InheritanceType        : None
                        InheritedObjectType    : GuidNULL
                        IsInherited            : False
                    #>

                    $parameters = @{
                        Id                    = $PSBoundParameters['Group']
                        LDAPPath              = 'CN=Schema,CN=Configuration,{0}' -f $Variables.defaultNamingContext
                        AdRight               = 'ExtendedRight'
                        AccessControlType     = 'Allow'
                        ObjectType            = $Variables.ExtendedRightsMap['Change Schema Master']
                        Verbose               = $false
                    }
                    # Check if RemoveRule switch is present.
                    If($PSBoundParameters['RemoveRule']) {
                        # Add the parameter to remove the rule
                        $parameters.Add('RemoveRule', $true)
                    }
                    Set-AclConstructor4 @parameters

                    $parameters = @{
                        Id                    = $PSBoundParameters['Group']
                        LDAPPath              = 'CN=Schema,CN=Configuration,{0}' -f $Variables.defaultNamingContext
                        AdRight               = 'WriteProperty'
                        AccessControlType     = 'Allow'
                        ObjectType            = $Variables.GuidMap['fSMORoleOwner']
                        Verbose               = $false
                    }
                    # Check if RemoveRule switch is present.
                    If($PSBoundParameters['RemoveRule']) {
                        # Add the parameter to remove the rule
                        $parameters.Add('RemoveRule', $true)
                    }
                    Set-AclConstructor4 @parameters
                }
                'DomainNaming'  {
                    <#
                        Get-AclAccessRule -LDAPpath 'CN=Partitions,CN=Configuration,DC=EguibarIT,DC=local' -SearchBy xxxx

                        ACENumber              : 1
                        DistinguishedName      : CN=Partitions,CN=Configuration,DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRightst : WriteProperty
                        AccessControlType      : Allow
                        ObjectType             : fSMORoleOwner [AttributeSchema]
                        InheritanceType        : None
                        InheritedObjectType    : GuidNULL
                        IsInherited            : False

                        ACENumber              : 2
                        DistinguishedName      : CN=Partitions,CN=Configuration,DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRightst : ExtendedRight
                        AccessControlType      : Allow
                        ObjectType             : Change Domain Master [Extended Rights]
                        InheritanceType        : None
                        InheritedObjectType    : GuidNULL
                        IsInherited            : False
                    #>

                    $parameters = @{
                        Id                    = $PSBoundParameters['Group']
                        LDAPPath              = 'CN=Partitions,CN=Configuration,{0}' -f $Variables.defaultNamingContext
                        AdRight               = 'WriteProperty'
                        AccessControlType     = 'Allow'
                        ObjectType            = $Variables.GuidMap['fSMORoleOwner']
                        Verbose               = $false
                    }
                    # Check if RemoveRule switch is present.
                    If($PSBoundParameters['RemoveRule']) {
                        # Add the parameter to remove the rule
                        $parameters.Add('RemoveRule', $true)
                    }
                    Set-AclConstructor4 @parameters

                    $parameters = @{
                        Id                    = $PSBoundParameters['Group']
                        LDAPPath              = 'CN=Partitions,CN=Configuration,{0}' -f $Variables.defaultNamingContext
                        AdRight               = 'ExtendedRight'
                        AccessControlType     = 'Allow'
                        ObjectType            = $Variables.ExtendedRightsMap['Change Domain Master']
                        Verbose               = $false
                    }
                    # Check if RemoveRule switch is present.
                    If($PSBoundParameters['RemoveRule']) {
                        # Add the parameter to remove the rule
                        $parameters.Add('RemoveRule', $true)
                    }
                    Set-AclConstructor4 @parameters
                }
                # Domain specific roles
                'Infrastructure' {
                    <#
                        Get-AclAccessRule -LDAPpath 'CN=Infrastructure,DC=EguibarIT,DC=local' -SearchBy xxxx

                        ACENumber              : 1
                        DistinguishedName      : CN=Infrastructure,DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRightst : WriteProperty
                        AccessControlType      : Allow
                        ObjectType             : fSMORoleOwner [AttributeSchema]
                        InheritanceType        : None
                        InheritedObjectType    : GuidNULL
                        IsInherited            : False

                        ACENumber              : 2
                        DistinguishedName      : CN=Infrastructure,DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRightst : ExtendedRight
                        AccessControlType      : Allow
                        ObjectType             : Change Infrastructure Master [Extended Rights]
                        InheritanceType        : None
                        InheritedObjectType    : GuidNULL
                        IsInherited            : False
                    #>

                    $parameters = @{
                        Id                    = $PSBoundParameters['Group']
                        LDAPPath              = 'CN=Infrastructure,{0}' -f $Variables.defaultNamingContext
                        AdRight               = 'WriteProperty'
                        AccessControlType     = 'Allow'
                        ObjectType            = $Variables.GuidMap['fSMORoleOwner']
                        Verbose               = $false
                    }
                    # Check if RemoveRule switch is present.
                    If($PSBoundParameters['RemoveRule']) {
                        # Add the parameter to remove the rule
                        $parameters.Add('RemoveRule', $true)
                    }
                    Set-AclConstructor4 @parameters

                    $parameters = @{
                        Id                    = $PSBoundParameters['Group']
                        LDAPPath              = 'CN=Infrastructure,{0}' -f $Variables.defaultNamingContext
                        AdRight               = 'ExtendedRight'
                        AccessControlType     = 'Allow'
                        ObjectType            = $Variables.ExtendedRightsMap['Change Infrastructure Master']
                        Verbose               = $false
                    }
                    # Check if RemoveRule switch is present.
                    If($PSBoundParameters['RemoveRule']) {
                        # Add the parameter to remove the rule
                        $parameters.Add('RemoveRule', $true)
                    }
                    Set-AclConstructor4 @parameters
                }
                'RID'   {
                    <#
                        Get-AclAccessRule -LDAPpath 'CN=RID Manager$,CN=System,DC=EguibarIT,DC=local' -SearchBy xxxx

                        ACENumber              : 1
                        DistinguishedName      : CN=RID Manager$,CN=System,DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRightst : WriteProperty
                        AccessControlType      : Allow
                        ObjectType             : fSMORoleOwner [AttributeSchema]
                        InheritanceType        : None
                        InheritedObjectType    : GuidNULL
                        IsInherited            : False

                        ACENumber              : 2
                        DistinguishedName      : CN=RID Manager$,CN=System,DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRightst : ExtendedRight
                        AccessControlType      : Allow
                        ObjectType             : Change Rid Master [Extended Rights]
                        InheritanceType        : None
                        InheritedObjectType    : GuidNULL
                        IsInherited            : False
                    #>

                    $parameters = @{
                        Id                    = $PSBoundParameters['Group']
                        LDAPPath              = 'CN=RID Manager$,CN=System,{0}' -f $Variables.defaultNamingContext
                        AdRight               = 'WriteProperty'
                        AccessControlType     = 'Allow'
                        ObjectType            = $Variables.GuidMap['fSMORoleOwner']
                        Verbose               = $false
                    }
                    # Check if RemoveRule switch is present.
                    If($PSBoundParameters['RemoveRule']) {
                        # Add the parameter to remove the rule
                        $parameters.Add('RemoveRule', $true)
                    }
                    Set-AclConstructor4 @parameters

                    $parameters = @{
                        Id                    = $PSBoundParameters['Group']
                        LDAPPath              = 'CN=RID Manager$,CN=System,{0}' -f $Variables.defaultNamingContext
                        AdRight               = 'ExtendedRight'
                        AccessControlType     = 'Allow'
                        ObjectType            = $Variables.ExtendedRightsMap['Change Rid Master']
                        Verbose               = $false
                    }
                    # Check if RemoveRule switch is present.
                    If($PSBoundParameters['RemoveRule']) {
                        # Add the parameter to remove the rule
                        $parameters.Add('RemoveRule', $true)
                    }
                    Set-AclConstructor4 @parameters
                }
                'PDC' {
                    <#
                        Get-AclAccessRule -LDAPpath 'DC=EguibarIT,DC=local' -SearchBy xxxx

                        ACENumber              : 1
                        DistinguishedName      : DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRightst : WriteProperty
                        AccessControlType      : Allow
                        ObjectType             : fSMORoleOwner [AttributeSchema]
                        InheritanceType        : None
                        InheritedObjectType    : GuidNULL
                        IsInherited            : False

                        ACENumber              : 2
                        DistinguishedName      : DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRightst : ExtendedRight
                        AccessControlType      : Allow
                        ObjectType             : Change PDC [Extended Rights]
                        InheritanceType        : None
                        InheritedObjectType    : GuidNULL
                        IsInherited            : False
                    #>

                    $parameters = @{
                        Id                    = $PSBoundParameters['Group']
                        LDAPPath              = $Variables.defaultNamingContext
                        AdRight               = 'WriteProperty'
                        AccessControlType     = 'Allow'
                        ObjectType            = $Variables.GuidMap['fSMORoleOwner']
                        Verbose               = $false
                    }
                    # Check if RemoveRule switch is present.
                    If($PSBoundParameters['RemoveRule']) {
                        # Add the parameter to remove the rule
                        $parameters.Add('RemoveRule', $true)
                    }
                    Set-AclConstructor4 @parameters

                    $parameters = @{
                        Id                    = $PSBoundParameters['Group']
                        LDAPPath              = $Variables.defaultNamingContext
                        AdRight               = 'ExtendedRight'
                        AccessControlType     = 'Allow'
                        ObjectType            = $Variables.ExtendedRightsMap['Change PDC']
                        Verbose               = $false
                    }
                    # Check if RemoveRule switch is present.
                    If($PSBoundParameters['RemoveRule']) {
                        # Add the parameter to remove the rule
                        $parameters.Add('RemoveRule', $true)
                    }
                    Set-AclConstructor4 @parameters
                }
            } #end Switch

            If($PSBoundParameters['RemoveRule']) {
                Write-Verbose -Message ('The right to transfer {1} role was revoked from {0}.' -f $PSBoundParameters['Group'], $role)
            } else {
                Write-Verbose -Message ('{0} now has the right to transfer {1} role.' -f $PSBoundParameters['Group'], $role)
            }
        } #End Foreach
    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
} # End Set-AdAclFMSOtransfer function

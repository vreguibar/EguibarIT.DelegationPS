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
                Get-AttributeSchemaHashTable                | EguibarIT.Delegation
                Get-ExtendedRightHashTable             | EguibarIT.Delegation
        .NOTES
            Version:         1.0
            DateModified:    26/Apr/2022
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    Param (

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
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
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New()

            # $Variables.GuidMap is empty. Call function to fill it up
            Write-Verbose -Message 'Variable $Variables.GuidMap is empty. Calling function to fill it up.'
            Get-AttributeSchemaHashTable

        Write-Verbose -Message 'Checking variable $Variables.ExtendedRightsMap. In case is empty a function is called to fill it up.'
        Get-ExtendedRightHashTable

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

    } #end Begin

    Process {
        # Process each of the FMSO roles
        foreach ($Role in $FSMOroles) {
            switch ($role) {
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

                    $Splat = @{
                        Id                = $CurrentGroup
                        LDAPPath          = 'CN=Schema,CN=Configuration,{0}' -f $Variables.defaultNamingContext
                        AdRight           = 'ExtendedRight'
                        AccessControlType = 'Allow'
                        ObjectType        = $Variables.ExtendedRightsMap['Change Schema Master']
                        Verbose           = $false
                    }
                    # Check if RemoveRule switch is present.
                    If ($PSBoundParameters['RemoveRule']) {

                        if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to transfer Schema Master?')) {
                            # Add the parameter to remove the rule
                            $Splat.Add('RemoveRule', $true)
                        } #end If
                    }

                    If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to transfer Schema Master?')) {
                        Set-AclConstructor4 @Splat
                    } #end If

                    $Splat = @{
                        Id                = $CurrentGroup
                        LDAPPath          = 'CN=Schema,CN=Configuration,{0}' -f $Variables.defaultNamingContext
                        AdRight           = 'WriteProperty'
                        AccessControlType = 'Allow'
                        ObjectType        = $Variables.GuidMap['fSMORoleOwner']
                        Verbose           = $false
                    }
                    # Check if RemoveRule switch is present.
                    If ($PSBoundParameters['RemoveRule']) {

                        if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to transfer Schema Master?')) {
                            # Add the parameter to remove the rule
                            $Splat.Add('RemoveRule', $true)
                        } #end If
                    } #end If

                    If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to transfer Schema Master?')) {
                        Set-AclConstructor4 @Splat
                    } #end If
                }
                'DomainNaming' {
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

                    $Splat = @{
                        Id                = $CurrentGroup
                        LDAPPath          = 'CN=Partitions,CN=Configuration,{0}' -f $Variables.defaultNamingContext
                        AdRight           = 'WriteProperty'
                        AccessControlType = 'Allow'
                        ObjectType        = $Variables.GuidMap['fSMORoleOwner']
                        Verbose           = $false
                    }
                    # Check if RemoveRule switch is present.
                    If ($PSBoundParameters['RemoveRule']) {

                        if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to transfer Domain Naming Master?')) {
                            # Add the parameter to remove the rule
                            $Splat.Add('RemoveRule', $true)
                        } #end If
                    } #end If

                    If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to transfer Domain Naming Master?')) {
                        Set-AclConstructor4 @Splat
                    } #end If

                    $Splat = @{
                        Id                = $CurrentGroup
                        LDAPPath          = 'CN=Partitions,CN=Configuration,{0}' -f $Variables.defaultNamingContext
                        AdRight           = 'ExtendedRight'
                        AccessControlType = 'Allow'
                        ObjectType        = $Variables.ExtendedRightsMap['Change Domain Master']
                        Verbose           = $false
                    }
                    # Check if RemoveRule switch is present.
                    If ($PSBoundParameters['RemoveRule']) {

                        if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to transfer Domain Naming Master?')) {
                            # Add the parameter to remove the rule
                            $Splat.Add('RemoveRule', $true)
                        } #end If
                    }

                    If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to transfer Domain Naming Master?')) {
                        Set-AclConstructor4 @Splat
                    } #end If
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

                    $Splat = @{
                        Id                = $CurrentGroup
                        LDAPPath          = 'CN=Infrastructure,{0}' -f $Variables.defaultNamingContext
                        AdRight           = 'WriteProperty'
                        AccessControlType = 'Allow'
                        ObjectType        = $Variables.GuidMap['fSMORoleOwner']
                        Verbose           = $false
                    }
                    # Check if RemoveRule switch is present.
                    If ($PSBoundParameters['RemoveRule']) {

                        if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to transfer Infrastructure Master?')) {
                            # Add the parameter to remove the rule
                            $Splat.Add('RemoveRule', $true)
                        } #end If
                    } #end If

                    If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to transfer Infrastructure Master?')) {
                        Set-AclConstructor4 @Splat
                    } #end If

                    $Splat = @{
                        Id                = $CurrentGroup
                        LDAPPath          = 'CN=Infrastructure,{0}' -f $Variables.defaultNamingContext
                        AdRight           = 'ExtendedRight'
                        AccessControlType = 'Allow'
                        ObjectType        = $Variables.ExtendedRightsMap['Change Infrastructure Master']
                        Verbose           = $false
                    }
                    # Check if RemoveRule switch is present.
                    If ($PSBoundParameters['RemoveRule']) {

                        if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to transfer Infrastructure Master?')) {
                            # Add the parameter to remove the rule
                            $Splat.Add('RemoveRule', $true)
                        } #end If
                    } #end If

                    If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to transfer Infrastructure Master?')) {
                        Set-AclConstructor4 @Splat
                    } #end If
                }
                'RID' {
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

                    $Splat = @{
                        Id                = $CurrentGroup
                        LDAPPath          = 'CN=RID Manager$,CN=System,{0}' -f $Variables.defaultNamingContext
                        AdRight           = 'WriteProperty'
                        AccessControlType = 'Allow'
                        ObjectType        = $Variables.GuidMap['fSMORoleOwner']
                        Verbose           = $false
                    }
                    # Check if RemoveRule switch is present.
                    If ($PSBoundParameters['RemoveRule']) {

                        if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to transfer RID Master?')) {
                            # Add the parameter to remove the rule
                            $Splat.Add('RemoveRule', $true)
                        } #end If
                    } #end If

                    If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to transfer RID Master?')) {
                        Set-AclConstructor4 @Splat
                    } #end If

                    $Splat = @{
                        Id                = $CurrentGroup
                        LDAPPath          = 'CN=RID Manager$,CN=System,{0}' -f $Variables.defaultNamingContext
                        AdRight           = 'ExtendedRight'
                        AccessControlType = 'Allow'
                        ObjectType        = $Variables.ExtendedRightsMap['Change Rid Master']
                        Verbose           = $false
                    }
                    # Check if RemoveRule switch is present.
                    If ($PSBoundParameters['RemoveRule']) {

                        if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to transfer RID Master?')) {
                            # Add the parameter to remove the rule
                            $Splat.Add('RemoveRule', $true)
                        } #end If
                    } #end If

                    If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to transfer RID Master?')) {
                        Set-AclConstructor4 @Splat
                    } #end If
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

                    $Splat = @{
                        Id                = $CurrentGroup
                        LDAPPath          = $Variables.defaultNamingContext
                        AdRight           = 'WriteProperty'
                        AccessControlType = 'Allow'
                        ObjectType        = $Variables.GuidMap['fSMORoleOwner']
                        Verbose           = $false
                    }
                    # Check if RemoveRule switch is present.
                    If ($PSBoundParameters['RemoveRule']) {

                        if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to transfer PDCemulator Master?')) {
                            # Add the parameter to remove the rule
                            $Splat.Add('RemoveRule', $true)
                        } #end If
                    } #end If

                    If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to transfer PDCemulator Master?')) {
                        Set-AclConstructor4 @Splat
                    } #end If

                    $Splat = @{
                        Id                = $CurrentGroup
                        LDAPPath          = $Variables.defaultNamingContext
                        AdRight           = 'ExtendedRight'
                        AccessControlType = 'Allow'
                        ObjectType        = $Variables.ExtendedRightsMap['Change PDC']
                        Verbose           = $false
                    }
                    # Check if RemoveRule switch is present.
                    If ($PSBoundParameters['RemoveRule']) {

                        if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to transfer PDCemulator Master?')) {
                            # Add the parameter to remove the rule
                            $Splat.Add('RemoveRule', $true)
                        } #end If
                    } #end If

                    If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to transfer PDCemulator Master?')) {
                        Set-AclConstructor4 @Splat
                    } #end If
                }
            } #end Switch

            If ($PSBoundParameters['RemoveRule']) {
                Write-Verbose -Message ('The right to transfer {1} role was revoked from {0}.' -f $PSBoundParameters['Group'], $role)
            } else {
                Write-Verbose -Message ('{0} now has the right to transfer {1} role.' -f $PSBoundParameters['Group'], $role)
            }
        } #End Foreach
    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating FSMO role transfer."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
} # End Set-AdAclFMSOtransfer function

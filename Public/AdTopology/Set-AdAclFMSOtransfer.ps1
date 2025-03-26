Function Set-AdAclFMSOtransfer {
    <#
        .SYNOPSIS
            Delegate the management rights of FSMO roles.

        .DESCRIPTION
            This function delegates permissions to transfer Flexible Single Master Operations (FSMO) roles
            to a specified group. It supports:

            - All five FSMO roles (Schema, Domain Naming, Infrastructure, RID, PDC)
            - Both forest-wide and domain-specific roles
            - Adding and removing delegations
            - Progress tracking and detailed logging
            - WhatIf/Confirm support for safe execution

            The function requires Enterprise Admin rights for forest-wide roles.

        .PARAMETER Group
            Security group that will receive FSMO transfer rights. Must be a valid AD group.
            Accepts pipeline input and name or Distinguished Name format.

        .PARAMETER FSMOroles
            Array of FSMO roles to delegate. Valid values:
            - Schema (forest-wide)
            - DomainNaming (forest-wide)
            - Infrastructure (domain-specific)
            - RID (domain-specific)
            - PDC (domain-specific)

        .PARAMETER RemoveRule
            If specified, removes the delegated permissions instead of adding them.
            Use with caution as this affects FSMO management capabilities.

        .EXAMPLE
            Set-AdAclFMSOtransfer -Group "SL_FSMOadmin" -FSMOroles "Schema", "Infrastructure"

            Delegates Schema and Infrastructure FSMO transfer rights to the specified group.

        .EXAMPLE
            Set-AdAclFMSOtransfer -Group "SL_FSMOadmin" -FSMOroles "PDC" -RemoveRule

            Removes PDC FSMO transfer rights from the specified group.

        .EXAMPLE
            "SG_FSMOAdmins" | Set-AdAclFMSOtransfer -FSMOroles "RID", "PDC" -WhatIf

            Shows what changes would be made for RID and PDC role delegation.

        .OUTPUTS
            [void]

        .NOTES
            Used Functions:
                Name                                 ║ Module
                ═════════════════════════════════════╬══════════════════════════════
                Set-AclConstructor4                  ║ EguibarIT.DelegationPS
                Get-AttributeSchemaHashTable         ║ EguibarIT.DelegationPS
                Get-ExtendedRightHashTable           ║ EguibarIT.DelegationPS
                Get-AdObjectType                     ║ EguibarIT.DelegationPS
                Write-Verbose                        ║ Microsoft.PowerShell.Utility
                Write-Error                          ║ Microsoft.PowerShell.Utility
        .NOTES
            Version:         1.1
            DateModified:    24/Mar/2025
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Public/AdTopology/Set-AdAclFMSOtransfer.ps1

        .LINK
            https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understanding-operations-masters

    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([void])]

    Param (

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        $Group,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Flexible Single Master Operations (FSMO) Roles to delegate.',
            Position = 1)]
        [ValidateSet('Schema', 'Infrastructure', 'DomainNaming', 'RID', 'PDC')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $FSMOroles,

        # PARAM3 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 2)]
        [Switch]
        $RemoveRule

    )

    Begin {

        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and $null -ne $Variables.HeaderDelegation) {
            $txt = ($Variables.HeaderDelegation -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end if

        ##############################
        # Module imports

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

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
                        ActiveDirectoryRights : ExtendedRight
                        AccessControlType      : Allow
                        ObjectType             : Change Schema Master [Extended Rights]
                        InheritanceType        : None
                        InheritedObjectType    : GuidNULL
                        IsInherited            : False

                        ACENumber              : 2
                        DistinguishedName      : CN=Schema,CN=Configuration,DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRights : WriteProperty
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

                        # Add the parameter to remove the rule
                        $Splat.Add('RemoveRule', $true)

                    }

                    If ($Force -or
                        $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to transfer Schema Master?')) {

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

                        # Add the parameter to remove the rule
                        $Splat.Add('RemoveRule', $true)

                    } #end If

                    If ($Force -or
                        $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to transfer Schema Master?')) {

                        Set-AclConstructor4 @Splat

                    } #end If
                } #end Schema

                'DomainNaming' {
                    <#
                        Get-AclAccessRule -LDAPpath 'CN=Partitions,CN=Configuration,DC=EguibarIT,DC=local' -SearchBy xxxx

                        ACENumber              : 1
                        DistinguishedName      : CN=Partitions,CN=Configuration,DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRights : WriteProperty
                        AccessControlType      : Allow
                        ObjectType             : fSMORoleOwner [AttributeSchema]
                        InheritanceType        : None
                        InheritedObjectType    : GuidNULL
                        IsInherited            : False

                        ACENumber              : 2
                        DistinguishedName      : CN=Partitions,CN=Configuration,DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRights : ExtendedRight
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

                        # Add the parameter to remove the rule
                        $Splat.Add('RemoveRule', $true)

                    } #end If

                    If ($Force -or
                        $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to transfer Domain Naming Master?')) {

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


                        # Add the parameter to remove the rule
                        $Splat.Add('RemoveRule', $true)

                    }

                    If ($Force -or
                        $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to transfer Domain Naming Master?')) {

                        Set-AclConstructor4 @Splat

                    } #end If
                } #end DomainNaming

                # Domain specific roles
                'Infrastructure' {
                    <#
                        Get-AclAccessRule -LDAPpath 'CN=Infrastructure,DC=EguibarIT,DC=local' -SearchBy xxxx

                        ACENumber              : 1
                        DistinguishedName      : CN=Infrastructure,DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRights : WriteProperty
                        AccessControlType      : Allow
                        ObjectType             : fSMORoleOwner [AttributeSchema]
                        InheritanceType        : None
                        InheritedObjectType    : GuidNULL
                        IsInherited            : False

                        ACENumber              : 2
                        DistinguishedName      : CN=Infrastructure,DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRights : ExtendedRight
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

                        # Add the parameter to remove the rule
                        $Splat.Add('RemoveRule', $true)

                    } #end If

                    If ($Force -or
                        $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to transfer Infrastructure Master?')) {

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

                        # Add the parameter to remove the rule
                        $Splat.Add('RemoveRule', $true)

                    } #end If

                    If ($Force -or
                        $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to transfer Infrastructure Master?')) {

                        Set-AclConstructor4 @Splat

                    } #end If
                } #end Infrastructure

                'RID' {
                    <#
                        Get-AclAccessRule -LDAPpath 'CN=RID Manager$,CN=System,DC=EguibarIT,DC=local' -SearchBy xxxx

                        ACENumber              : 1
                        DistinguishedName      : CN=RID Manager$,CN=System,DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRights : WriteProperty
                        AccessControlType      : Allow
                        ObjectType             : fSMORoleOwner [AttributeSchema]
                        InheritanceType        : None
                        InheritedObjectType    : GuidNULL
                        IsInherited            : False

                        ACENumber              : 2
                        DistinguishedName      : CN=RID Manager$,CN=System,DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRights : ExtendedRight
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

                        # Add the parameter to remove the rule
                        $Splat.Add('RemoveRule', $true)

                    } #end If

                    If ($Force -or
                        $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to transfer RID Master?')) {

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

                        # Add the parameter to remove the rule
                        $Splat.Add('RemoveRule', $true)

                    } #end If

                    If ($Force -or
                        $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to transfer RID Master?')) {

                        Set-AclConstructor4 @Splat

                    } #end If
                } #end RID

                'PDC' {
                    <#
                        Get-AclAccessRule -LDAPpath 'DC=EguibarIT,DC=local' -SearchBy xxxx

                        ACENumber              : 1
                        DistinguishedName      : DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRights : WriteProperty
                        AccessControlType      : Allow
                        ObjectType             : fSMORoleOwner [AttributeSchema]
                        InheritanceType        : None
                        InheritedObjectType    : GuidNULL
                        IsInherited            : False

                        ACENumber              : 2
                        DistinguishedName      : DC=EguibarIT,DC=local
                        IdentityReference      : EguibarIT\XXXX
                        ActiveDirectoryRights : ExtendedRight
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

                        # Add the parameter to remove the rule
                        $Splat.Add('RemoveRule', $true)

                    } #end If

                    If ($Force -or
                        $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to transfer PDCemulator Master?')) {

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

                        # Add the parameter to remove the rule
                        $Splat.Add('RemoveRule', $true)

                    } #end If

                    If ($Force -or
                        $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to transfer PDCemulator Master?')) {

                        Set-AclConstructor4 @Splat

                    } #end If
                } #end PDC
            } #end Switch

            If ($PSBoundParameters['RemoveRule']) {

                Write-Verbose -Message ('
                    The right to transfer {1} role was revoked from {0}.' -f $PSBoundParameters['Group'], $role
                )

            } else {

                Write-Verbose -Message ('
                    {0} now has the right to transfer {1} role.' -f $PSBoundParameters['Group'], $role
                )

            } #end If-Else
        } #End Foreach
    } #end Process

    End {

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'delegating FSMO role transfer.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End
} # End Set-AdAclFMSOtransfer function

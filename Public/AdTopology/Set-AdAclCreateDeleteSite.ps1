﻿function Set-AdAclCreateDeleteSite {
    <#
        .Synopsis
            The function will delegate the permission for a group to
            Create and Delete Sites

        .DESCRIPTION
            This function delegates or removes permissions for a specified
            group to create and delete Active Directory Sites within the domain.

        .EXAMPLE
            Set-AdAclCreateDeleteSite -Group "SG_SiteAdmins_XXXX"

        .EXAMPLE
            Set-AdAclCreateDeleteSite -Group "SG_SiteAdmins_XXXX" -RemoveRule

        .PARAMETER Group
            Specifies the name of the group to delegate permissions to.

        .PARAMETER RemoveRule
            If specified, the function will remove the delegated permissions from the group.

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor4                    | EguibarIT.DelegationPS
                Set-AclConstructor5                    | EguibarIT.DelegationPS
                Set-AclConstructor6                    | EguibarIT.DelegationPS
                Get-AttributeSchemaHashTable           | EguibarIT.DelegationPS
                Get-CurrentErrorToDisplay              | EguibarIT.DelegationPS

        .NOTES
            Version:         1.2
            DateModified:    8/Feb/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Group Name which will get the delegation',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        $Group,

        # PARAM2 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'If present, the function will not ask for confirmation when performing actions.',
            Position = 2)]
        [Switch]
        $Force
    )

    begin {

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
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # $Variables.GuidMap is empty. Call function to fill it up
        Write-Verbose -Message 'Variable $Variables.GuidMap is empty. Calling function to fill it up.'
        Get-AttributeSchemaHashTable

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

    } #end Begin

    process {

        <#
            ACE number: 1
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights  : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : GuidNULL
                    InheritanceType : Descendents
                InheritedObjectType : site [ClassSchema]
                        IsInherited = False
        #>
        try {
            Write-Verbose 'Attempting to set ACL 1 for permissions...'
            $Splat = @{
                Id                    = $CurrentGroup
                LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext
                AdRight               = 'CreateChild', 'DeleteChild'
                AccessControlType     = 'Allow'
                ObjectType            = $Constants.guidNull
                AdSecurityInheritance = 'Descendents'
                InheritedObjectType   = $Variables.GuidMap['site']
            }
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {
                # Add the parameter to remove the rule
                if ($Force -or $PSCmdlet.ShouldProcess($Group, 'Remove permissions for creating and deleting AD sites')) {
                    $Splat.Add('RemoveRule', $true)
                }
            }
            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate permissions for creating and deleting AD sites?')) {
                Set-AclConstructor6 @Splat
            }
        } Catch {
            Write-Error -Message 'Error when delegating Create/Delete site'
            throw
        } #end Try-Catch



        <#
            ACE number: 2
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights  : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : site [ClassSchema]
                    InheritanceType : All
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        try {
            Write-Verbose 'Attempting to set ACL 2 for permissions...'
            $Splat = @{
                Id                    = $CurrentGroup
                LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext
                AdRight               = 'CreateChild', 'DeleteChild'
                AccessControlType     = 'Allow'
                ObjectType            = $Variables.GuidMap['site']
                AdSecurityInheritance = 'All'
            }
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {
                if ($Force -or $PSCmdlet.ShouldProcess($Group, 'Remove permissions for creating and deleting AD sites')) {

                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)
                }
            }
            if ($Force -or $PSCmdlet.ShouldProcess("$Group", 'Delegate permissions for creating and deleting AD sites')) {
                Set-AclConstructor5 @Splat
            }
        } Catch {
            Write-Error -Message 'Error when delegating Create/Delete site'
            throw
        } #end Try-Catch



        <#
            ACE number: 3
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights  : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : nTDSSiteSettings [ClassSchema]
                    InheritanceType : Descendents
                InheritedObjectType : site [ClassSchema]
                        IsInherited = False
        #>
        try {
            Write-Verbose 'Attempting to set ACL 3 for permissions...'
            $Splat = @{
                Id                    = $CurrentGroup
                LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext
                AdRight               = 'CreateChild', 'DeleteChild'
                AccessControlType     = 'Allow'
                ObjectType            = $Variables.GuidMap['nTDSSiteSettings']
                AdSecurityInheritance = 'Descendents'
                InheritedObjectType   = $Variables.GuidMap['site']
            }
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {
                if ($Force -or $PSCmdlet.ShouldProcess($Group, 'Remove permissions for creating and deleting AD sites')) {

                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)
                }
            }
            if ($Force -or $PSCmdlet.ShouldProcess("$Group", 'Delegate permissions for creating and deleting AD sites')) {
                Set-AclConstructor6 @Splat
            }
        } Catch {
            Write-Error -Message 'Error when delegating Create/Delete site'
            throw
        } #end Try-Catch



        <#
            ACE number: 4
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : nTDSDSA [ClassSchema]
                    InheritanceType : Descendents
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        try {
            Write-Verbose 'Attempting to set ACL 4 for permissions...'
            $Splat = @{
                Id                    = $CurrentGroup
                LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext
                AdRight               = 'CreateChild', 'DeleteChild'
                AccessControlType     = 'Allow'
                ObjectType            = $Variables.GuidMap['nTDSDSA']
                AdSecurityInheritance = 'Descendents'
            }
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {
                if ($Force -or $PSCmdlet.ShouldProcess($Group, 'Remove permissions for creating and deleting AD sites')) {

                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)
                }
            }
            if ($Force -or $PSCmdlet.ShouldProcess("$Group", 'Delegate permissions for creating and deleting AD sites')) {
                Set-AclConstructor5 @Splat
            }
        } Catch {
            Write-Error -Message 'Error when delegating Create/Delete site'
            throw
        } #end Try-Catch


        <#
            ACE number: 5
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights : WriteDacl
                  AccessControlType : Allow
                         ObjectType : nTDSDSA [ClassSchema]
                    InheritanceType : Descendents
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        try {
            Write-Verbose 'Attempting to set ACL 5 for permissions...'
            $Splat = @{
                Id                = $CurrentGroup
                LDAPPath          = 'CN=Sites,{0}' -f $Variables.configurationNamingContext
                AdRight           = 'WriteDacl'
                AccessControlType = 'Allow'
                ObjectType        = $Variables.GuidMap['nTDSDSA']
            }
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {
                if ($Force -or $PSCmdlet.ShouldProcess($Group, 'Remove permissions for creating and deleting AD sites')) {

                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)
                }
            }
            if ($Force -or $PSCmdlet.ShouldProcess("$Group", 'Delegate permissions for creating and deleting AD sites')) {
                Set-AclConstructor4 @Splat
            }
        } Catch {
            Write-Error -Message 'Error when delegating Create/Delete site'
            throw
        } #end Try-Catch



        <#
            ACE number: 6
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : server [ClassSchema]
                    InheritanceType : Descendents
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        try {
            Write-Verbose 'Attempting to set ACL 6 for permissions...'
            $Splat = @{
                Id                    = $CurrentGroup
                LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext
                AdRight               = 'CreateChild', 'DeleteChild'
                AccessControlType     = 'Allow'
                ObjectType            = $Variables.GuidMap['server']
                AdSecurityInheritance = 'Descendents'
            }
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {
                if ($Force -or $PSCmdlet.ShouldProcess($Group, 'Remove permissions for creating and deleting AD sites')) {

                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)
                }
            }
            if ($Force -or $PSCmdlet.ShouldProcess("$Group", 'Delegate permissions for creating and deleting AD sites')) {
                Set-AclConstructor5 @Splat
            }
        } Catch {
            Write-Error -Message 'Error when delegating Create/Delete site'
            throw
        } #end Try-Catch



        <#

            ACE number: 7
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : nTDSConnection [ClassSchema]
                    InheritanceType : Descendents
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        try {
            Write-Verbose 'Attempting to set ACL 7 for permissions...'
            $Splat = @{
                Id                    = $CurrentGroup
                LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext
                AdRight               = 'CreateChild', 'DeleteChild'
                AccessControlType     = 'Allow'
                ObjectType            = $Variables.GuidMap['nTDSConnection']
                AdSecurityInheritance = 'Descendents'
            }
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {
                if ($Force -or $PSCmdlet.ShouldProcess($Group, 'Remove permissions for creating and deleting AD sites')) {

                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)
                }
            }
            if ($Force -or $PSCmdlet.ShouldProcess("$Group", 'Delegate permissions for creating and deleting AD sites')) {
                Set-AclConstructor5 @Splat
            }
        } Catch {
            Write-Error -Message 'Error when delegating Create/Delete site'
            throw
        } #end Try-Catch



        <#
            ACE number: 8
            --------------------------------------------------------
                 IdentityReference : XXX
            ActiveDirectoryRights : GenericAll
            AccessControlType      : Allow
            ObjectType             : GuidNULL
            InheritanceType        : Descendents
            InheritedObjectType    : serversContainer [ClassSchema]
            IsInherited            = False
        #>
        try {
            Write-Verbose 'Attempting to set ACL 8 for permissions...'
            $Splat = @{
                Id                    = $CurrentGroup
                LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext
                AdRight               = 'GenericAll'
                AccessControlType     = 'Allow'
                InheritedObjectType   = $Variables.GuidMap['serversContainer']
                ObjectType            = $Constants.guidNull
                AdSecurityInheritance = 'Descendents'
            }
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {
                if ($Force -or $PSCmdlet.ShouldProcess($Group, 'Remove permissions for creating and deleting AD sites')) {

                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)
                }
            }
            if ($Force -or $PSCmdlet.ShouldProcess("$Group", 'Delegate permissions for creating and deleting AD sites')) {
                Set-AclConstructor6 @Splat
            }
        } Catch {
            Write-Error -Message 'Error when delegating Create/Delete site'
            throw
        } #end Try-Catch

        <#
            ACE number: 9
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights : GenericAll
             AccessControlType      : Allow
             ObjectType             : GuidNULL
             InheritanceType        : Descendents
             InheritedObjectType    : msDNS-ServerSettings [ClassSchema]
             IsInherited            = False
        #>
        try {
            Write-Verbose 'Attempting to set ACL 9 for permissions...'
            $Splat = @{
                Id                    = $CurrentGroup
                LDAPPath              = 'CN=Sites,{0}' -f $Variables.configurationNamingContext
                AdRight               = 'GenericAll'
                AccessControlType     = 'Allow'
                InheritedObjectType   = $Variables.GuidMap['msDNS-ServerSettings']
                ObjectType            = $Constants.guidNull
                AdSecurityInheritance = 'Descendents'
            }
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {
                if ($Force -or $PSCmdlet.ShouldProcess($Group, 'Remove permissions for creating and deleting AD sites')) {

                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)
                }
            }
            if ($Force -or $PSCmdlet.ShouldProcess("$Group", 'Delegate permissions for creating and deleting AD sites')) {
                Set-AclConstructor6 @Splat
            }
        } Catch {
            Write-Error -Message 'Error when delegating Create/Delete site'
            throw
        } #end Try-Catch


    } #end Process

    end {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0}' -f $PSBoundParameters['Group'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0}' -f $PSBoundParameters['Group'])
        } #end If-Else

        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'delegating Change/Delete Site.'
        )
        Write-Verbose -Message $txt
    } #end End
}

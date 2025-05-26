function Set-AdAclCreateDeleteVolume {
    <#
        .SYNOPSIS
            Delegates permissions to a group for creating and deleting Volume (Shared Folder) objects in an OU.

        .DESCRIPTION
            The Set-AdAclCreateDeleteVolume function delegates the necessary Active Directory permissions
            to allow a specified group to create and delete volume objects (shared folders) within a
            specified container or organizational unit (OU).

            The function adds two Access Control Entries (ACEs) to the specified OU:
            1. An ACE granting GenericAll rights to volume objects, which enables full control over volume objects
            2. An ACE granting CreateChild and DeleteChild rights specifically for volume objects

            These permissions allow the delegated group to create new shared folders, delete existing
            shared folders, and manage all properties of shared folders within the specified OU.

            When the -RemoveRule parameter is used, the function removes these permissions instead
            of granting them.

        .PARAMETER Group
            Identity of the group getting the delegation. Can be specified as SamAccountName,
            DistinguishedName, ObjectGUID, or SID.

        .PARAMETER LDAPpath
            Distinguished Name of the object (or container) where the permissions are going to
            be configured. This is typically an Organizational Unit.

        .PARAMETER RemoveRule
            If present, the access rule will be removed instead of being added.

        .PARAMETER Force
            If present, the function will not ask for confirmation when performing actions.

        .EXAMPLE
            Set-AdAclCreateDeleteVolume -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=SharedFolders,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"

            Delegates the permissions for the group "SG_SiteAdmins_XXXX" to create and delete
            volume objects (shared folders) in the specified OU.

        .EXAMPLE
            Set-AdAclCreateDeleteVolume -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=SharedFolders,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule

            Removes the permissions for the group "SG_SiteAdmins_XXXX" to create and delete
            volume objects in the specified OU.

        .EXAMPLE
            $Splat = @{
                Group = "SG_SiteAdmins_XXXX"
                LDAPPath = "OU=SharedFolders,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
                Force = $true
            }
            Set-AdAclCreateDeleteVolume @Splat

            Delegates the permissions without prompting for confirmation.

        .INPUTS
            System.String for Group and LDAPpath parameters.

        .OUTPUTS
            System.Void

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Set-AclConstructor5                        ║ EguibarIT.DelegationPS
                Get-AttributeSchemaHashTable               ║ EguibarIT.DelegationPS
                Get-FunctionDisplay                        ║ EguibarIT.DelegationPS
                Get-AdObjectType                           ║ EguibarIT.DelegationPS
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Test-IsValidDN                             ║ EguibarIT.DelegationPS

        .NOTES
            Version:         2.0
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS

        .COMPONENT
            Active Directory

        .ROLE
            Security

        .FUNCTIONALITY
            Volume Management, Shared Folders, Delegation of Control
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        $Group,

        #PARAM2 Distinguished Name of the OU were the groups can be changed
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the object (or container) where the permissions are going to be configured.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ }, ErrorMessage = 'DistinguishedName provided is not valid! Please Check.')]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        # PARAM3 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'If present, the function will not ask for confirmation when performing actions.',
            Position = 3)]
        [Switch]
        $Force
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

        Write-Verbose -Message 'Checking variable $Variables.GuidMap. In case is empty a function is called to fill it up.'
        Get-AttributeSchemaHashTable

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

    } #end Begin

    Process {
        <#
            ACE number: 2
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : volume [ClassSchema]
                    InheritanceType : All
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['volume']
            AdSecurityInheritance = 'All'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for Volume?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions for Volume?')) {
            Set-AclConstructor5 @Splat
        } #end If

        <#
            ACE number: 1
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights : GenericAll
                  AccessControlType : Allow
                         ObjectType : volume [ClassSchema]
                    InheritanceType : Descendents
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['volume']
            AdSecurityInheritance = 'Descendents'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for Volume?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions for Volume?')) {
            Set-AclConstructor5 @Splat
        } #end If
    } #end Process

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0} on {1}' -f $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0} on {1}' -f $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath'])
        } #end If-Else

        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'delegating Create/Delete Volume.'
        )
        Write-Verbose -Message $txt
    } #end END
}

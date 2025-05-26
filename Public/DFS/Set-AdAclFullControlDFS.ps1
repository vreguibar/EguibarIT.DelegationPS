function Set-AdAclFullControlDFS {
    <#
        .SYNOPSIS
            Delegates full control permissions for DFS (Distributed File System) management.

        .DESCRIPTION
            The Set-AdAclFullControlDFS function delegates comprehensive DFS management permissions
            by granting full control over both DFS Global Settings and DFS Configuration objects
            in Active Directory.

            The function adds two Access Control Entries (ACEs):
            1. An ACE granting GenericAll rights to the DFSR-GlobalSettings object
            2. An ACE granting GenericAll rights to the Dfs-Configuration object

            These permissions allow the delegated group to fully manage DFS namespaces and
            replication settings within the domain. This includes creating, modifying, and
            deleting DFS namespaces, configuring replication settings, and managing DFS
            topology.

            When the -RemoveRule parameter is used, the function removes these permissions
            instead of granting them.

        .PARAMETER Group
            Identity of the group getting the delegation. Can be specified as SamAccountName,
            DistinguishedName, ObjectGUID, or SID. This should be a group dedicated to DFS
            administration.

        .PARAMETER RemoveRule
            If present, the access rules will be removed instead of being added.

        .PARAMETER Force
            If present, the function will not ask for confirmation when performing actions.

        .EXAMPLE
            Set-AdAclFullControlDFS -Group "SG_DfsAdmins_XXXX"

            Delegates full control permissions over DFS to the group "SG_DfsAdmins_XXXX".

        .EXAMPLE
            Set-AdAclFullControlDFS -Group "SG_DfsAdmins_XXXX" -RemoveRule

            Removes previously delegated DFS full control permissions from the specified group.

        .EXAMPLE
            $Splat = @{
                Group = "SG_DfsAdmins_XXXX"
                Force = $true
            }
            Set-AdAclFullControlDFS @Splat

            Delegates full control permissions without prompting for confirmation.

        .INPUTS
            System.String for the Group parameter.

        .OUTPUTS
            System.Void

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Set-AclConstructor4                        ║ EguibarIT.DelegationPS
                Get-AdDomain                               ║ ActiveDirectory
                Get-FunctionDisplay                        ║ EguibarIT.DelegationPS
                Get-AdObjectType                           ║ EguibarIT.DelegationPS
                Write-Verbose                              ║ Microsoft.PowerShell.Utility

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
            DFS Management, Delegation of Control
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

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

    } #end Begin

    Process {
        <#
            ACENumber              : 1
            IdentityReference      : EguibarIT\XXX
            ActiveDirectoryRights : GenericAll
            AccessControlType      : Allow
            ObjectType             : GuidNULL
            InheritanceType        : All
            InheritedObjectType    : GuidNULL
            IsInherited            : False
        #>
        $Splat = @{
            Id                = $CurrentGroup
            LDAPPath          = 'CN=DFSR-GlobalSettings,CN=System,{0}' -f $Variables.defaultNamingContext
            AdRight           = 'GenericAll'
            AccessControlType = 'Allow'
            ObjectType        = $Constants.guidNull
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for Full Control DFS Global Settings?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions for Full Control DFS Global Settings?')) {
            Set-AclConstructor4 @Splat
        } #end If

        <#
            ACENumber              : 1
            DistinguishedName      : CN=Dfs-Configuration,CN=System,DC=EguibarIT,DC=local
            IdentityReference      : EguibarIT\SL_DfsRight
            ActiveDirectoryRights : GenericAll
            AccessControlType      : Allow
            ObjectType             : GuidNULL
            InheritanceType        : All
            InheritedObjectType    : GuidNULL
            IsInherited            : False
        #>
        $Splat = @{
            Id                = $CurrentGroup
            LDAPPath          = 'CN=Dfs-Configuration,CN=System,{0}' -f $Variables.defaultNamingContext
            AdRight           = 'GenericAll'
            AccessControlType = 'Allow'
            ObjectType        = $Constants.guidNull
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for Full Control DFS Configuration?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions for Full Control DFS Configuration?')) {
            Set-AclConstructor4 @Splat
        } #end If
    }

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0}' -f $PSBoundParameters['Group'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0}' -f $PSBoundParameters['Group'])
        } #end If-Else

        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'delegating DFS Full control.'
        )
        Write-Verbose -Message $txt
    } #end END
}

function Set-AdDirectoryReplication {
    <#
        .SYNOPSIS
            Delegates directory replication permissions to a specified group across all naming contexts.

        .DESCRIPTION
            The Set-AdDirectoryReplication function delegates comprehensive Active Directory replication
            permissions to a specified security group. It configures multiple replication-related
            rights across all naming contexts in the forest.

            The function grants the following specific permissions:
            - Monitor Active Directory Replication
            - Replicating Directory Changes
            - Replicating Directory Changes All
            - Replicating Directory Changes In Filtered Set
            - Manage Replication Topology
            - Replication Synchronization
            - msDS-NC-Replica-Locations management

            These permissions enable the delegated group to perform essential replication tasks including
            monitoring replication health, initiating replication, and managing replication topology.

            Important Security Note: On Windows Server 2022 and newer versions, this operation may
            require additional privileges beyond Domain Admin and Enterprise Admin due to enhanced
            security controls.

        .PARAMETER Group
            Identity of the group getting the delegation. Can be specified as SamAccountName,
            DistinguishedName, ObjectGUID, or SID. The group must exist in Active Directory
            and should be dedicated to replication management.

        .PARAMETER RemoveRule
            If present, the access rules will be removed instead of being added. Use with
            caution as this affects critical replication capabilities.

        .PARAMETER Force
            If present, the function will not ask for confirmation when performing actions.
            Use with caution as this affects critical directory replication settings.

        .EXAMPLE
            Set-AdDirectoryReplication -Group "SG_ReplicationAdmins"

            Delegates comprehensive replication permissions to the group "SG_ReplicationAdmins",
            enabling them to manage and monitor Active Directory replication.

        .EXAMPLE
            Set-AdDirectoryReplication -Group "SG_ReplicationAdmins" -RemoveRule -Force

            Removes all previously delegated replication permissions from the group without
            prompting for confirmation.

        .EXAMPLE
            $Splat = @{
                Group = "SG_ReplicationAdmins"
                Force = $true
            }
            Set-AdDirectoryReplication @Splat

            Delegates replication permissions using splatting without confirmation prompts.

        .INPUTS
            System.String for the Group parameter.

        .OUTPUTS
            System.Void

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Set-AclConstructor4                        ║ EguibarIT.DelegationPS
                Get-AttributeSchemaHashTable               ║ EguibarIT.DelegationPS
                Get-ExtendedRightHashTable                 ║ EguibarIT.DelegationPS
                Get-AdObjectType                           ║ EguibarIT.DelegationPS
                Test-AdminPrivilege                        ║ EguibarIT.DelegationPS
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility

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
            Security, Replication

        .FUNCTIONALITY
            AD Replication Management, Delegation of Control
                Write-Error                          ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.4
            DateModified:    9/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([void])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation',
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

        # Check for administrative rights
        # Get current user and role
        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        #$WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
        $WindowsPrincipal = [System.Security.Principal.WindowsPrincipal]::New($CurrentUser)

        # Check if running as administrator
        if (-not $WindowsPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $ErrorMsg = 'Error: This function requires elevation. Please run PowerShell as Administrator.'
            Write-Error -Message $ErrorMsg
            throw $ErrorMsg
        } #end if

        # $Variables.GuidMap is empty. Call function to fill it up
        Write-Verbose -Message 'Variable $Variables.GuidMap is empty. Calling function to fill it up.'
        Get-AttributeSchemaHashTable

        Write-Verbose -Message 'Checking variable $Variables.ExtendedRightsMap. In case is empty a function is called to fill it up.'
        Get-ExtendedRightHashTable

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

    } #end Begin

    Process {
        try {
            # Iterate through all naming contexts
            Foreach ($CurrentContext in $Variables.namingContexts) {
                Write-Verbose -Message ('Processing naming context: {0}' -f $CurrentContext)

                ####################
                # Monitor Active Directory Replication
                <#
                    ACENumber              :
                    DistinguishedName      : Current Naming Context
                    IdentityReference      : EguibarIT\XXX
                    ActiveDirectoryRights : ExtendedRight
                    AccessControlType      : Allow
                    ObjectType             : Monitor Active Directory Replication [Extended Rights]
                    InheritanceType        : None
                    InheritedObjectType    : GuidNULL
                    IsInherited            : False
                #>
                $Splat = @{
                    Id                = $CurrentGroup
                    LDAPPath          = $CurrentContext
                    AdRight           = 'ExtendedRight'
                    AccessControlType = 'Allow'
                    ObjectType        = $Variables.ExtendedRightsMap['Monitor Active Directory Replication']
                }
                # Check if RemoveRule switch is present.
                If ($PSBoundParameters['RemoveRule']) {

                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)

                } #end If

                If ($Force -or
                    $PSCmdlet.ShouldProcess($PSBoundParameters['Group'],
                        'Delegate the permissions to Monitor Active Directory Replication?')) {

                    Set-AclConstructor4 @Splat

                } #end If

                ####################
                # Replicating Directory Changes
                <#
                ACENumber              :
                DistinguishedName      : Current Naming Context
                IdentityReference      : EguibarIT\XXX
                ActiveDirectoryRights : ExtendedRight
                AccessControlType      : Allow
                ObjectType             : Replicating Directory Changes [Extended Rights]
                InheritanceType        : None
                InheritedObjectType    : GuidNULL
                IsInherited            : False
            #>
                $Splat = @{
                    Id                = $CurrentGroup
                    LDAPPath          = $CurrentContext
                    AdRight           = 'ExtendedRight'
                    AccessControlType = 'Allow'
                    ObjectType        = $Variables.ExtendedRightsMap['Replicating Directory Changes']
                }
                # Check if RemoveRule switch is present.
                If ($PSBoundParameters['RemoveRule']) {

                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)

                } #end If

                If ($Force -or
                    $PSCmdlet.ShouldProcess($PSBoundParameters['Group'],
                        'Delegate the permissions to Replicating Directory Changes?')) {

                    Set-AclConstructor4 @Splat -ErrorAction Stop

                } #end If

                ####################
                # Replicating Directory Changes All
                <#
                ACENumber              :
                DistinguishedName      : Current Naming Context
                IdentityReference      : EguibarIT\XXX
                ActiveDirectoryRights : ExtendedRight
                AccessControlType      : Allow
                ObjectType             : Replicating Directory Changes All [Extended Rights]
                InheritanceType        : None
                InheritedObjectType    : GuidNULL
                IsInherited            : False
            #>
                $Splat = @{
                    Id                = $CurrentGroup
                    LDAPPath          = $CurrentContext
                    AdRight           = 'ExtendedRight'
                    AccessControlType = 'Allow'
                    ObjectType        = $Variables.ExtendedRightsMap['Replicating Directory Changes All']
                }
                # Check if RemoveRule switch is present.
                If ($PSBoundParameters['RemoveRule']) {

                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)

                } #end If

                If ($Force -or
                    $PSCmdlet.ShouldProcess($PSBoundParameters['Group'],
                        'Delegate the permissions to Replicating Directory Changes All?')) {

                    Set-AclConstructor4 @Splat

                } #end If

                ####################
                # Replicating Directory Changes In Filtered Set
                <#
                ACENumber              :
                DistinguishedName      : Current Naming Context
                IdentityReference      : EguibarIT\XXX
                ActiveDirectoryRights : ExtendedRight
                AccessControlType      : Allow
                ObjectType             : Replicating Directory Changes In Filtered Set [Extended Rights]
                InheritanceType        : None
                InheritedObjectType    : GuidNULL
                IsInherited            : False
            #>
                $Splat = @{
                    Id                = $CurrentGroup
                    LDAPPath          = $CurrentContext
                    AdRight           = 'ExtendedRight'
                    AccessControlType = 'Allow'
                    ObjectType        = $Variables.ExtendedRightsMap['Replicating Directory Changes In Filtered Set']
                }
                # Check if RemoveRule switch is present.
                If ($PSBoundParameters['RemoveRule']) {

                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)

                } #end If

                If ($Force -or
                    $PSCmdlet.ShouldProcess($PSBoundParameters['Group'],
                        'Delegate the permissions to Replicating Directory Changes In Filtered Set?')) {

                    Set-AclConstructor4 @Splat

                } #end If

                ####################
                # Manage Replication Topology
                <#
                ACENumber              :
                DistinguishedName      : Current Naming Context
                IdentityReference      : EguibarIT\XXX
                ActiveDirectoryRights : ExtendedRight
                AccessControlType      : Allow
                ObjectType             : Manage Replication Topology [Extended Rights]
                InheritanceType        : None
                InheritedObjectType    : GuidNULL
                IsInherited            : False
            #>
                $Splat = @{
                    Id                = $CurrentGroup
                    LDAPPath          = $CurrentContext
                    AdRight           = 'ExtendedRight'
                    AccessControlType = 'Allow'
                    ObjectType        = $Variables.ExtendedRightsMap['Manage Replication Topology']
                }
                # Check if RemoveRule switch is present.
                If ($PSBoundParameters['RemoveRule']) {

                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)

                } #end If

                If ($Force -or
                    $PSCmdlet.ShouldProcess($PSBoundParameters['Group'],
                        'Delegate the permissions to Manage Replication Topology?')) {

                    Set-AclConstructor4 @Splat

                } #end If

                ####################
                # Replication Synchronization
                <#
                ACENumber              :
                DistinguishedName      : Current Naming Context
                IdentityReference      : EguibarIT\XXX
                ActiveDirectoryRights : ExtendedRight
                AccessControlType      : Allow
                ObjectType             : Replication Synchronization [Extended Rights]
                InheritanceType        : All
                InheritedObjectType    : GuidNULL
                IsInherited            : False
            #>
                $Splat = @{
                    Id                = $CurrentGroup
                    LDAPPath          = $CurrentContext
                    AdRight           = 'ExtendedRight'
                    AccessControlType = 'Allow'
                    ObjectType        = $Variables.ExtendedRightsMap['Replication Synchronization']
                }
                # Check if RemoveRule switch is present.
                If ($PSBoundParameters['RemoveRule']) {

                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)

                } #end If

                If ($Force -or
                    $PSCmdlet.ShouldProcess($PSBoundParameters['Group'],
                        'Delegate the permissions to Replication Synchronization?')) {

                    Set-AclConstructor4 @Splat

                } #end If

            } #end Foreach


            $Splat = @{
                Filter      = '*'
                SearchBase  = $Variables.PartitionsContainer
                SearchScope = 'OneLevel'
                Properties  = 'name', 'nCName', 'msDS-NC-Replica-Locations'
            }
            $partitions = Get-ADObject @Splat | Select-Object name, nCName, msDS-NC-Replica-Locations

            ####################
            # Configure partitions attribute "msDS-NC-Replica-Locations"
            foreach ($part in $partitions) {
                Write-Verbose -Message "Processing partition: $($part.name)"

                If ($part.'msDS-NC-Replica-Locations') {
                    $partitionPath = 'CN={0},CN=Partitions,CN=Configuration,{1}' -f $part.name, $Variables.defaultNamingContext
                    Write-Verbose -Message ('Processing msDS-NC-Replica-Locations for {0}' -f $partitionPath)

                    #
                    $Splat = @{
                        Id                = $CurrentGroup
                        LDAPPath          = $partitionPath
                        AdRight           = 'ReadProperty'
                        AccessControlType = 'Allow'
                        ObjectType        = $Variables.GuidMap['msDS-NC-Replica-Locations']
                    }
                    # Check if RemoveRule switch is present.
                    If ($PSBoundParameters['RemoveRule']) {

                        # Add the parameter to remove the rule
                        $Splat.Add('RemoveRule', $true)

                    } #end If

                    If ($Force -or
                        $PSCmdlet.ShouldProcess($PSBoundParameters['Group'],
                            "Delegate read permissions to msDS-NC-Replica-Locations on $($part.name)?")) {

                        Set-AclConstructor4 @Splat

                    } #end If

                    $Splat = @{
                        Id                = $CurrentGroup
                        LDAPPath          = $partitionPath
                        AdRight           = 'WriteProperty'
                        AccessControlType = 'Allow'
                        ObjectType        = $Variables.GuidMap['msDS-NC-Replica-Locations']
                    }
                    # Check if RemoveRule switch is present.
                    If ($PSBoundParameters['RemoveRule']) {

                        # Add the parameter to remove the rule
                        $Splat.Add('RemoveRule', $true)

                    } #end If

                    If ($Force -or
                        $PSCmdlet.ShouldProcess($PSBoundParameters['Group'],
                            "Delegate write permissions to msDS-NC-Replica-Locations on $($part.name)?")) {

                        Set-AclConstructor4 @Splat

                    } #end If

                } #end If
            } #end Foreach
        } Catch {
            $ErrorMsg = ('Error: {0}' -f $_.Exception.Message)
            Write-Error -Message $ErrorMsg
            throw $ErrorMsg
        } Finally {
            # Cleanup code if needed
            Write-Verbose -Message 'Cleanup code executed.'
        }
    }#end Process

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0}' -f $PSBoundParameters['Group'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0}' -f $PSBoundParameters['Group'])
        } #end If-Else

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'delegating replication.'
            )
            Write-Verbose -Message $txt
        } #end If

    } #end End
} #end function Set-AdDirectoryReplication

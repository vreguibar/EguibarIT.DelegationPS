function Set-AdDirectoryReplication {
    <#
        .SYNOPSIS
            Delegates directory replication permissions to a specified group.

        .DESCRIPTION
            This function configures Active Directory replication permissions for a specified group.
            It delegates the following rights across all naming contexts:

            - Monitor Active Directory Replication
            - Replicating Directory Changes
            - Replicating Directory Changes All
            - Replicating Directory Changes In Filtered Set
            - Manage Replication Topology
            - Replication Synchronization
            - msDS-NC-Replica-Locations management

            The function implements proper error handling and requires appropriate permissions.

        .PARAMETER Group
            Security group that will receive replication rights. Must be a valid AD group.
            Accepts pipeline input and name or Distinguished Name format.

        .PARAMETER RemoveRule
            If specified, removes the delegated permissions instead of adding them.
            Use with caution as this affects replication capabilities.

        .EXAMPLE
            Set-AdDirectoryReplication -Group "SG_ReplicationAdmins"

            Delegates replication permissions to the specified group.

        .EXAMPLE
            Set-AdDirectoryReplication -Group "SG_ReplicationAdmins" -RemoveRule

            Removes replication permissions from the specified group.

        .EXAMPLE
            "SG_ReplicationAdmins" | Set-AdDirectoryReplication -WhatIf

            Shows what changes would be made without actually making them.

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
            Version:         1.3
            DateModified:    24/Mar/2025
            LasModifiedBy:   Vicente Rodriguez Eguibar
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

        # Iterate through all naming contexts
        Foreach ($CurrentContext in $Variables.namingContexts) {
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
                $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to Monitor Active Directory Replication?')) {

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
                $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to Replicating Directory Changes?')) {

                Set-AclConstructor4 @Splat

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
                $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to Replicating Directory Changes All?')) {

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
                $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to Replicating Directory Changes In Filtered Set?')) {

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
                $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to Manage Replication Topology?')) {

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
                $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to Replication Synchronization?')) {

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

            If ($part.'msDS-NC-Replica-Locations') {

                #
                $Splat = @{
                    Id                = $CurrentGroup
                    LDAPPath          = 'CN={0},CN=Partitions,CN=Configuration,{1}' -f $part.name, $Variables.defaultNamingContext
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
                    $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to msDS-NC-Replica-Locations?')) {

                    Set-AclConstructor4 @Splat

                } #end If

                $Splat = @{
                    Id                = $CurrentGroup
                    LDAPPath          = 'CN={0},CN=Partitions,CN=Configuration,{1}' -f $part.name, $Variables.defaultNamingContext
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
                    $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to msDS-NC-Replica-Locations?')) {

                    Set-AclConstructor4 @Splat

                } #end If

            } #end If
        } #end Foreach

    } #end Process

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

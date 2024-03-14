function Set-AdDirectoryReplication {
    <#
        .Synopsis
            The function will delegate the premission for a group to replicate the directory
        .DESCRIPTION
            TConfigures the configuration container to delegate the permissions to a group so it can replicate the directory
        .EXAMPLE
            Set-AdDirectoryReplication -Group "SG_SiteAdmins_XXXX"
        .EXAMPLE
            Set-AdDirectoryReplication -Group "SG_SiteAdmins_XXXX" -RemoveRule
        .PARAMETER Group
            [STRING] for the Delegated Group Name
        .PARAMETER RemoveRule
            [SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor4                    | EguibarIT.Delegation
                Get-AttributeSchemaHashTable                | EguibarIT.Delegation
                New-ExtenderRightHashTable             | EguibarIT.Delegation
        .NOTES
            Version:         1.2
            DateModified:    4/May/2022
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        [String]
        $Group,

        # PARAM2 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 1)]
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
        [Hashtable]$Splat = [hashtable]::New()

        If ( ($null -eq $Variables.GuidMap) -and
                 ($Variables.GuidMap -ne 0) -and
                 ($Variables.GuidMap -ne '') -and
                 (   ($Variables.GuidMap -isnot [array]) -or
                     ($Variables.GuidMap.Length -ne 0)) -and
                 ($Variables.GuidMap -ne $false)
        ) {

            # $Variables.GuidMap is empty. Call function to fill it up
            Write-Verbose -Message 'Variable $Variables.GuidMap is empty. Calling function to fill it up.'
            Get-AttributeSchemaHashTable

        } #end If

        If ( ($null -eq $Variables.ExtendedRightsMap) -and
                 ($Variables.ExtendedRightsMap -ne 0) -and
                 ($Variables.ExtendedRightsMap -ne '') -and
                 (   ($Variables.ExtendedRightsMap -isnot [array]) -or
                     ($Variables.ExtendedRightsMap.Length -ne 0)) -and
                 ($Variables.ExtendedRightsMap -ne $false)
        ) {
            # $Variables.ExtendedRightsMap is empty. Call function to fill it up
            Write-Verbose -Message 'Variable $Variables.ExtendedRightsMap is empty. Calling function to fill it up.'
            New-ExtenderRightHashTable
        } #end If
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
                ActiveDirectoryRightst : ExtendedRight
                AccessControlType      : Allow
                ObjectType             : Monitor Active Directory Replication [Extended Rights]
                InheritanceType        : None
                InheritedObjectType    : GuidNULL
                IsInherited            : False
            #>
            $Splat = @{
                Id                = $PSBoundParameters['Group']
                LDAPPath          = $CurrentContext
                AdRight           = 'ExtendedRight'
                AccessControlType = 'Allow'
                ObjectType        = $Variables.ExtendedRightsMap['Monitor Active Directory Replication']
            }
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {

                if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to Monitor Active Directory Replication?')) {
                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)
                } #end If
            } #end If

            If ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to Monitor Active Directory Replication?')) {
                Set-AclConstructor4 @Splat
            } #end If

            ####################
            # Replicating Directory Changes
            <#
                ACENumber              :
                DistinguishedName      : Current Naming Context
                IdentityReference      : EguibarIT\XXX
                ActiveDirectoryRightst : ExtendedRight
                AccessControlType      : Allow
                ObjectType             : Replicating Directory Changes [Extended Rights]
                InheritanceType        : None
                InheritedObjectType    : GuidNULL
                IsInherited            : False
            #>
            $Splat = @{
                Id                = $PSBoundParameters['Group']
                LDAPPath          = $CurrentContext
                AdRight           = 'ExtendedRight'
                AccessControlType = 'Allow'
                ObjectType        = $Variables.ExtendedRightsMap['Replicating Directory Changes']
            }
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {

                if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to Replicating Directory Changes?')) {
                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)
                } #end If
            } #end If

            If ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to Replicating Directory Changes?')) {
                Set-AclConstructor4 @Splat
            } #end If

            ####################
            # Replicating Directory Changes All
            <#
                ACENumber              :
                DistinguishedName      : Current Naming Context
                IdentityReference      : EguibarIT\XXX
                ActiveDirectoryRightst : ExtendedRight
                AccessControlType      : Allow
                ObjectType             : Replicating Directory Changes All [Extended Rights]
                InheritanceType        : None
                InheritedObjectType    : GuidNULL
                IsInherited            : False
            #>
            $Splat = @{
                Id                = $PSBoundParameters['Group']
                LDAPPath          = $CurrentContext
                AdRight           = 'ExtendedRight'
                AccessControlType = 'Allow'
                ObjectType        = $Variables.ExtendedRightsMap['Replicating Directory Changes All']
            }
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {

                if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to Replicating Directory Changes All?')) {
                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)
                } #end If
            } #end If

            If ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to Replicating Directory Changes All?')) {
                Set-AclConstructor4 @Splat
            } #end If

            ####################
            # Replicating Directory Changes In Filtered Set
            <#
                ACENumber              :
                DistinguishedName      : Current Naming Context
                IdentityReference      : EguibarIT\XXX
                ActiveDirectoryRightst : ExtendedRight
                AccessControlType      : Allow
                ObjectType             : Replicating Directory Changes In Filtered Set [Extended Rights]
                InheritanceType        : None
                InheritedObjectType    : GuidNULL
                IsInherited            : False
            #>
            $Splat = @{
                Id                = $PSBoundParameters['Group']
                LDAPPath          = $CurrentContext
                AdRight           = 'ExtendedRight'
                AccessControlType = 'Allow'
                ObjectType        = $Variables.ExtendedRightsMap['Replicating Directory Changes In Filtered Set']
            }
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {

                if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to Replicating Directory Changes In Filtered Set?')) {
                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)
                } #end If
            } #end If

            If ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to Replicating Directory Changes In Filtered Set?')) {
                Set-AclConstructor4 @Splat
            } #end If

            ####################
            # Manage Replication Topology
            <#
                ACENumber              :
                DistinguishedName      : Current Naming Context
                IdentityReference      : EguibarIT\XXX
                ActiveDirectoryRightst : ExtendedRight
                AccessControlType      : Allow
                ObjectType             : Manage Replication Topology [Extended Rights]
                InheritanceType        : None
                InheritedObjectType    : GuidNULL
                IsInherited            : False
            #>
            $Splat = @{
                Id                = $PSBoundParameters['Group']
                LDAPPath          = $CurrentContext
                AdRight           = 'ExtendedRight'
                AccessControlType = 'Allow'
                ObjectType        = $Variables.ExtendedRightsMap['Manage Replication Topology']
            }
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {

                if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to Manage Replication Topology?')) {
                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)
                } #end If
            } #end If

            If ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to Manage Replication Topology?')) {
                Set-AclConstructor4 @Splat
            } #end If

            ####################
            # Replication Synchronization
            <#
                ACENumber              :
                DistinguishedName      : Current Naming Context
                IdentityReference      : EguibarIT\XXX
                ActiveDirectoryRightst : ExtendedRight
                AccessControlType      : Allow
                ObjectType             : Replication Synchronization [Extended Rights]
                InheritanceType        : All
                InheritedObjectType    : GuidNULL
                IsInherited            : False
            #>
            $Splat = @{
                Id                = $PSBoundParameters['Group']
                LDAPPath          = $CurrentContext
                AdRight           = 'ExtendedRight'
                AccessControlType = 'Allow'
                ObjectType        = $Variables.ExtendedRightsMap['Replication Synchronization']
            }
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {

                if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to Replication Synchronization?')) {
                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)
                } #end If
            } #end If

            If ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to Replication Synchronization?')) {
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
                    Id                = $PSBoundParameters['Group']
                    LDAPPath          = 'CN={0},CN=Partitions,CN=Configuration,{1}' -f $part.name, $Variables.defaultNamingContext
                    AdRight           = 'ReadProperty'
                    AccessControlType = 'Allow'
                    ObjectType        = $Variables.GuidMap['msDS-NC-Replica-Locations']
                }
                # Check if RemoveRule switch is present.
                If ($PSBoundParameters['RemoveRule']) {

                    if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to msDS-NC-Replica-Locations?')) {
                        # Add the parameter to remove the rule
                        $Splat.Add('RemoveRule', $true)
                    } #end If
                } #end If

                If ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to msDS-NC-Replica-Locations?')) {
                    Set-AclConstructor4 @Splat
                } #end If

                $Splat = @{
                    Id                = $PSBoundParameters['Group']
                    LDAPPath          = 'CN={0},CN=Partitions,CN=Configuration,{1}' -f $part.name, $Variables.defaultNamingContext
                    AdRight           = 'WriteProperty'
                    AccessControlType = 'Allow'
                    ObjectType        = $Variables.GuidMap['msDS-NC-Replica-Locations']
                }
                # Check if RemoveRule switch is present.
                If ($PSBoundParameters['RemoveRule']) {

                    if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to msDS-NC-Replica-Locations?')) {
                        # Add the parameter to remove the rule
                        $Splat.Add('RemoveRule', $true)
                    } #end If
                } #end If

                If ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions to msDS-NC-Replica-Locations?')) {
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

        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
}

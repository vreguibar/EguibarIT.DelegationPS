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
                New-GuidObjectHashTable                | EguibarIT.Delegation
                New-ExtenderRightHashTable             | EguibarIT.Delegation
        .NOTES
            Version:         1.2
            DateModified:    4/May/2022
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Low')]

    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference','Identity','Trustee','GroupID')]
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
        } #end If

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
        } #end If
    }
    Process {

        # Iterate through all naming contexts
        Foreach($CurrentContext in $Variables.namingContexts) {
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
            $parameters = @{
                Id                    = $PSBoundParameters['Group']
                LDAPPath              = $CurrentContext
                AdRight               = 'ExtendedRight'
                AccessControlType     = 'Allow'
                ObjectType            = $Variables.ExtendedRightsMap['Monitor Active Directory Replication']
            }
            # Check if RemoveRule switch is present.
            If($PSBoundParameters['RemoveRule']) {
                # Add the parameter to remove the rule
                $parameters.Add('RemoveRule', $true)
            }
            Set-AclConstructor4 @parameters

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
            $parameters = @{
                Id                    = $PSBoundParameters['Group']
                LDAPPath              = $CurrentContext
                AdRight               = 'ExtendedRight'
                AccessControlType     = 'Allow'
                ObjectType            = $Variables.ExtendedRightsMap['Replicating Directory Changes']
            }
            # Check if RemoveRule switch is present.
            If($PSBoundParameters['RemoveRule']) {
                # Add the parameter to remove the rule
                $parameters.Add('RemoveRule', $true)
            }
            Set-AclConstructor4 @parameters

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
            $parameters = @{
                Id                    = $PSBoundParameters['Group']
                LDAPPath              = $CurrentContext
                AdRight               = 'ExtendedRight'
                AccessControlType     = 'Allow'
                ObjectType            = $Variables.ExtendedRightsMap['Replicating Directory Changes All']
            }
            # Check if RemoveRule switch is present.
            If($PSBoundParameters['RemoveRule']) {
                # Add the parameter to remove the rule
                $parameters.Add('RemoveRule', $true)
            }
            Set-AclConstructor4 @parameters

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
            $parameters = @{
                Id                    = $PSBoundParameters['Group']
                LDAPPath              = $CurrentContext
                AdRight               = 'ExtendedRight'
                AccessControlType     = 'Allow'
                ObjectType            = $Variables.ExtendedRightsMap['Replicating Directory Changes In Filtered Set']
            }
            # Check if RemoveRule switch is present.
            If($PSBoundParameters['RemoveRule']) {
                # Add the parameter to remove the rule
                $parameters.Add('RemoveRule', $true)
            }
            Set-AclConstructor4 @parameters

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
            $parameters = @{
                Id                    = $PSBoundParameters['Group']
                LDAPPath              = $CurrentContext
                AdRight               = 'ExtendedRight'
                AccessControlType     = 'Allow'
                ObjectType            = $Variables.ExtendedRightsMap['Manage Replication Topology']
            }
            # Check if RemoveRule switch is present.
            If($PSBoundParameters['RemoveRule']) {
                # Add the parameter to remove the rule
                $parameters.Add('RemoveRule', $true)
            }
            Set-AclConstructor4 @parameters

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
            $parameters = @{
                Id                    = $PSBoundParameters['Group']
                LDAPPath              = $CurrentContext
                AdRight               = 'ExtendedRight'
                AccessControlType     = 'Allow'
                ObjectType            = $Variables.ExtendedRightsMap['Replication Synchronization']
            }
            # Check if RemoveRule switch is present.
            If($PSBoundParameters['RemoveRule']) {
                # Add the parameter to remove the rule
                $parameters.Add('RemoveRule', $true)
            }
            Set-AclConstructor4 @parameters

        } #end Foreach

        $partitions = Get-ADObject -Filter * -SearchBase $Variables.PartitionsContainer -SearchScope OneLevel -Properties name,nCName,msDS-NC-Replica-Locations | Select-Object name,nCName,msDS-NC-Replica-Locations

        ####################
        # Configure partitions attribute "msDS-NC-Replica-Locations"
        foreach ($part in $partitions) {
            If($part."msDS-NC-Replica-Locations") {

                #
                $parameters = @{
                    Id                    = $PSBoundParameters['Group']
                    LDAPPath              = 'CN={0},CN=Partitions,CN=Configuration,{1}' -f $part.name, $Variables.defaultNamingContext
                    AdRight               = 'ReadProperty'
                    AccessControlType     = 'Allow'
                    ObjectType            = $Variables.GuidMap['msDS-NC-Replica-Locations']
                }
                # Check if RemoveRule switch is present.
                If($PSBoundParameters['RemoveRule']) {
                    # Add the parameter to remove the rule
                    $parameters.Add('RemoveRule', $true)
                }
                Set-AclConstructor4 @parameters

                $parameters = @{
                    Id                    = $PSBoundParameters['Group']
                    LDAPPath              = 'CN={0},CN=Partitions,CN=Configuration,{1}' -f $part.name, $Variables.defaultNamingContext
                    AdRight               = 'WriteProperty'
                    AccessControlType     = 'Allow'
                    ObjectType            = $Variables.GuidMap['msDS-NC-Replica-Locations']
                }
                # Check if RemoveRule switch is present.
                If($PSBoundParameters['RemoveRule']) {
                    # Add the parameter to remove the rule
                    $parameters.Add('RemoveRule', $true)
                }
                Set-AclConstructor4 @parameters

            } #end If
        } #end Foreach

    } #end Process
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
}

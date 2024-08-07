function Set-AdAclPromoteDomain {
    <#
        .Synopsis
            The function will delegate the premission for a group to Promote and Demote Domain Controllers
        .DESCRIPTION
            The function will delegate the premission for a group to Promote and Demote Domain Controllers
        .EXAMPLE
            Set-AdAclPromoteDomain -Group "SG_SiteAdmins_XXXX" -StagingOU "OU=InfraStaging,OU=Infra,OU=Admin,DC=EguibarIT,DC=local"
        .EXAMPLE
            Set-AdAclPromoteDomain -Group "SG_SiteAdmins_XXXX" -StagingOU "OU=InfraStaging,OU=Infra,OU=Admin,DC=EguibarIT,DC=local" -RemoveRule
        .PARAMETER Group
            [STRING] for the Delegated Group Name
        .PARAMETER StagingOU
            [STRING] DistinguishedName of the Staging OU. OU must exist and Server must be present here before starting the Promotion process.
        .PARAMETER RemoveRule
            [SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor4                    | EguibarIT.DelegationPS
                Set-AclConstructor5                    | EguibarIT.DelegationPS
                Get-AttributeSchemaHashTable           | EguibarIT.DelegationPS
                Get-ExtendedRightHashTable             | EguibarIT.DelegationPS
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
        $Group,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'DistinguishedName of the Staging OU. OU must exist and Server must be present here before starting the Promotion process.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $StagingOU,

        # PARAM2 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 2)]
        [Switch]
        $RemoveRule
    )
    Begin {


        $txt = ($constants.Header -f (Get-Date).ToShortDateString(), $MyInvocation.Mycommand, (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        Write-Verbose -Message 'Checking variable $Variables.GuidMap. In case is empty a function is called to fill it up.'
        Get-AttributeSchemaHashTable

        Write-Verbose -Message 'Checking variable $Variables.ExtendedRightsMap. In case is empty a function is called to fill it up.'
        Get-ExtendedRightHashTable

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

    } #end Begin

    Process {

        # Each defined "Naming Context" must have these permissions
        # Variable $Variables.namingContexts contains all available naming contexts
        # the CMDLet "Set-AdDirectoryReplication" does grants all requiered rights in all NC
        # except for the "Add/Remove Replica In Domain"

        Set-AdDirectoryReplication -Group $PSBoundParameters['Group']

        Foreach ($Context in $Variables.namingContexts) {

            ####################
            # Add/Remove Replica In Domain
            $Splat = @{
                Id                = $CurrentGroup
                LDAPPath          = $Context
                AdRight           = 'ExtendedRight'
                AccessControlType = 'Allow'
                ObjectType        = $Variables.ExtendedRightsMap['Add/Remove Replica In Domain']
            }
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {

                if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for Add/Remove Replica In Domain?')) {
                    # Add the parameter to remove the rule
                    $Splat.Add('RemoveRule', $true)
                } #end If
            } #end If

            If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for Add/Remove Replica In Domain?')) {
                Set-AclConstructor4 @Splat
            } #end If


            ####################
            # Configure msDS-NC-RO-Replica-Locations on all NC
            # Not sure if ACENumber 1 is needed (ReadProperty, GenericExecute).
            # Included in DirRepl CMDlet
            <#
                ACENumber             : 1
                Id                    : EguibarIT\XXX
                LDAPpath              : CN=EguibarIT,CN=Partitions,CN=Configuration,DC=EguibarIT,DC=local
                AdRight               : ReadProperty, GenericExecute
                AccessControlType     : Allow
                ObjectType            : All [GuidNULL]
                AdSecurityInheritance : None
                InheritedObjectType   : All [GuidNULL]
                IsInherited           : False
            #>


            <#
                ACENumber             : 2
                IdentityReference     : EguibarIT\XXX
                LDAPpath              : CN=EguibarIT,CN=Partitions,CN=Configuration,DC=EguibarIT,DC=local
                AdRight               : WriteProperty
                AccessControlType     : Allow
                ObjectType            : msDS-NC-RO-Replica-Locations [attributeSchema]
                AdSecurityInheritance : None
                InheritedObjectType   : All [GuidNULL]
                IsInherited           : False
            #>

        } #end ForEach


        # Needed permissions to create/Manage site
        # All these permissions are already on the following CMDlets

        Set-AdAclCreateDeleteSite -Group $CurrentGroup
        Set-AdAclChangeSite -Group $CurrentGroup

        ####################
        # Grant permissions on Sites
        <#
            ACENumber              : 1
            DistinguishedName      : CN=Sites,CN=Configuration,DC=EguibarIT,DC=local
            IdentityReference      : EguibarIT\XXXX
            ActiveDirectoryRightst : CreateChild
            AccessControlType      : Allow
            ObjectType             : nTDSDSA [ClassSchema]
            InheritanceType        : Descendents
            InheritedObjectType    : GuidNULL
            IsInherited            : False

            ACENumber              : 2
            DistinguishedName      : CN=Sites,CN=Configuration,DC=EguibarIT,DC=local
            IdentityReference      : EguibarIT\XXXX
            ActiveDirectoryRightst : WriteDacl
            AccessControlType      : Allow
            ObjectType             : GuidNULL
            InheritanceType        : Descendents
            InheritedObjectType    : nTDSDSA [ClassSchema]
            IsInherited            : False

            ACENumber              : 3
            DistinguishedName      : CN=Sites,CN=Configuration,DC=EguibarIT,DC=local
            IdentityReference      : EguibarIT\XXXX
            ActiveDirectoryRightst : CreateChild
            AccessControlType      : Allow
            ObjectType             : server [ClassSchema]
            InheritanceType        : Descendents
            InheritedObjectType    : GuidNULL
            IsInherited            : False

            ACENumber              : 4
            DistinguishedName      : CN=Sites,CN=Configuration,DC=EguibarIT,DC=local
            IdentityReference      : EguibarIT\XXXX
            ActiveDirectoryRightst : CreateChild
            AccessControlType      : Allow
            ObjectType             : nTDSConnection [ClassSchema]
            InheritanceType        : Descendents
            InheritedObjectType    : GuidNULL
            IsInherited            : False
        #>


        ####################
        # Prepare Staging container for to-be-promoted server
        # In our DM the server staging is: "OU=InfraStaging,OU=Infra,OU=Admin,DC=EguibarIT,DC=local"
        If ($PSBoundParameters['StagingOU']) {
            $existingOU = Get-ADOrganizationalUnit -Filter { DistinguishedName -like $StagingOU } -ErrorAction SilentlyContinue

            If (-not($existingOU)) {
                $parameters = @{
                    Message           = 'Staging OU is a controlled OU where the server to be promoted resides. Computer object must have the corresponding permissions.'
                    Category          = ObjectNotFound
                    CategoryReason    = 'Staging OU could not be found!'
                    RecommendedAction = 'Ensure Staging OU {0} exists and is accessible.' -f $PSBoundParameters['StagingOU']
                }
                Write-Error @parameters
            } else {
                Write-Verbose -Message ('Staging OU found ({0}). Setting the permissions.' -f $existingOU)

                <#
                    ACENumber             : 1
                    Id                    : EguibarIT\XXX
                    LDAPpath              : OU=InfraStaging,OU=Infra,OU=Admin,DC=EguibarIT,DC=local
                    AdRight               : WriteProperty
                    AccessControlType     : Allow
                    ObjectType            : servicePrincipalName [attributeSchema]
                    AdSecurityInheritance : Descendents
                    InheritedObjectType   : computer [classSchema]
                    IsInherited           : False

                    ACENumber             : 2
                    Id                    : EguibarIT\XXX
                    LDAPpath              : OU=InfraStaging,OU=Infra,OU=Admin,DC=EguibarIT,DC=local
                    AdRight               : WriteProperty
                    AccessControlType     : Allow
                    ObjectType            : serverReference [attributeSchema]
                    AdSecurityInheritance : Descendents
                    InheritedObjectType   : computer [classSchema]
                    IsInherited           : False

                    ACENumber             : 3
                    Id                    : EguibarIT\XXX
                    LDAPpath              : OU=InfraStaging,OU=Infra,OU=Admin,DC=EguibarIT,DC=local
                    AdRight               : WriteProperty
                    AccessControlType     : Allow
                    ObjectType            : userAccountControl [attributeSchema]
                    AdSecurityInheritance : Descendents
                    InheritedObjectType   : computer [classSchema]
                    IsInherited           : False

                    ACENumber             : 4
                    Id                    : EguibarIT\XXX
                    LDAPpath              : OU=InfraStaging,OU=Infra,OU=Admin,DC=EguibarIT,DC=local
                    AdRight               : WriteProperty
                    AccessControlType     : Allow
                    ObjectType            : cn [attributeSchema]
                    AdSecurityInheritance : Descendents
                    InheritedObjectType   : computer [classSchema]
                    IsInherited           : False

                    ACENumber             : 5
                    Id                    : EguibarIT\XXX
                    LDAPpath              : OU=InfraStaging,OU=Infra,OU=Admin,DC=EguibarIT,DC=local
                    AdRight               : WriteProperty
                    AccessControlType     : Allow
                    ObjectType            : name [attributeSchema]
                    AdSecurityInheritance : Descendents
                    InheritedObjectType   : computer [classSchema]
                    IsInherited           : False

                    ACENumber             : 6
                    Id                    : EguibarIT\XXX
                    LDAPpath              : OU=InfraStaging,OU=Infra,OU=Admin,DC=EguibarIT,DC=local
                    AdRight               : WriteProperty
                    AccessControlType     : Allow
                    ObjectType            : distinguishedName [attributeSchema]
                    AdSecurityInheritance : Descendents
                    InheritedObjectType   : computer [classSchema]
                    IsInherited           : False

                    ACENumber             : 7
                    Id                    : EguibarIT\XXX
                    LDAPpath              : OU=InfraStaging,OU=Infra,OU=Admin,DC=EguibarIT,DC=local
                    AdRight               : DeleteChild
                    AccessControlType     : Allow
                    ObjectType            : computer [classSchema]
                    AdSecurityInheritance : None
                    InheritedObjectType   : All [GuidNULL]
                    IsInherited           : False
                #>

            } #end If-Else
        } #end If

        ####################
        # Set the necessary permissions on the domain controllers OU

        $Splat = @{
            Group    = $CurrentGroup
            LDAPPath = 'DC=Domain Controllers,{0}' -f $Variables.AdDN
        }

        # Create/Delete Computers
        Set-AdAclCreateDeleteComputer @Splat

        # Reset Computer Password
        Set-AdAclResetComputerPassword @Splat

        # Change Computer Password
        Set-AdAclChangeComputerPassword @Splat

        # Validated write to DNS host name
        Set-AdAclValidateWriteDnsHostName @Splat

        # Validated write to SPN
        Set-AdAclValidateWriteSPN @Splat

        # Change Computer Account Restriction
        Set-AdAclComputerAccountRestriction @Splat

        # Change DNS Hostname Info
        Set-AdAclDnsInfo @Splat

        # Change MS TerminalServices info
        Set-AdAclMsTsGatewayInfo @Splat

        # Access to BitLocker & TMP info
        Set-AdAclBitLockerTPM @Splat


    } #end Process

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0}' -f $PSBoundParameters['Group'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0}' -f $PSBoundParameters['Group'])
        } #end If-Else

        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating DCPromote."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
} #end Function Set-AdAclPromoteDomain

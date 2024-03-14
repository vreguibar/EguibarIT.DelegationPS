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
                Set-AclConstructor4                    | N/A - separate PowerShell script
                Set-AclConstructor5                    | N/A - separate PowerShell script
                Get-AttributeSchemaHashTable                | N/A - separate PowerShell script
                New-ExtenderRightHashTable             | N/A - separate PowerShell script
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
        [String]
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

        ####################
        # Add/remove replica in domain
        $Splat = @{
            Id                = $PSBoundParameters['Group']
            LDAPPath          = $Variables.defaultNamingContext
            AdRight           = 'ExtendedRight'
            AccessControlType = 'Allow'
            ObjectType        = $extendedrightsmap['Add/remove replica in domain']
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for Add/remove replica in domain?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for Add/remove replica in domain?')) {
            Set-AclConstructor4 @Splat
        } #end If

        ####################
        # Grant special permissions on Sites
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
        #>

        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,CN=Configuration,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'CreateChild'
            AccessControlType     = 'Allow'
            ObjectType            = $guidmap['nTDSDSA']
            AdSecurityInheritance = 'Descendents'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for nTDSDSA?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for nTDSDSA?')) {
            Set-AclConstructor5 @Splat
        } #end If

        <#
            ACENumber              : 2
            DistinguishedName      : CN=Sites,CN=Configuration,DC=EguibarIT,DC=local
            IdentityReference      : EguibarIT\XXXX
            ActiveDirectoryRightst : WriteDacl
            AccessControlType      : Allow
            ObjectType             : GuidNULL
            InheritanceType        : Descendents
            InheritedObjectType    : nTDSDSA [ClassSchema]
            IsInherited            : False
        #>
        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,CN=Configuration,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'WriteDacl'
            AccessControlType     = 'Allow'
            ObjectType            = $guidmap['nTDSDSA']
            AdSecurityInheritance = 'Descendents'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for nTDSDSA?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for nTDSDSA?')) {
            Set-AclConstructor5 @Splat
        } #end If

        <#
            ACENumber              : 3
            DistinguishedName      : CN=Sites,CN=Configuration,DC=EguibarIT,DC=local
            IdentityReference      : EguibarIT\XXXX
            ActiveDirectoryRightst : CreateChild
            AccessControlType      : Allow
            ObjectType             : server [ClassSchema]
            InheritanceType        : Descendents
            InheritedObjectType    : GuidNULL
            IsInherited            : False
        #>
        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,CN=Configuration,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'CreateChild'
            AccessControlType     = 'Allow'
            ObjectType            = $guidmap['server']
            AdSecurityInheritance = 'Descendents'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for server?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for server?')) {
            Set-AclConstructor5 @Splat
        } #end If

        <#
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
        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,CN=Configuration,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'CreateChild'
            AccessControlType     = 'Allow'
            ObjectType            = $guidmap['nTDSConnection']
            AdSecurityInheritance = 'Descendents'
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for nTDSConnection?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for nTDSConnection?')) {
            Set-AclConstructor5 @Splat
        } #end If


        ####################
        # Prepare Staging container for to-be-promoted server
        If ($StagingOU) {
            $existingOU = Get-ADOrganizationalUnit -Filter { DistinguishedName -like $StagingOU } -ErrorAction SilentlyContinue

            If (-not($existingOU)) {
                $parameters = @{
                    Message           = 'Staging OU is a controlled OU where the server to be promoted resides. Computer object must have the corresponding permissions.'
                    Category          = ObjectNotFound
                    CategoryReason    = 'Staging OU could not be found!'
                    RecommendedAction = 'Ensure Staging OU {0} exists and is accessible.' -f $existingOU.DistinguishedName
                }
                Write-Error @parameters
            } #end If
        } #end If

        ####################
        # Set the necessary permissions on the domain controllers OU

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
    } #end END
} #end Function Set-AdAclPromoteDomain

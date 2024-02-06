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
                New-GuidObjectHashTable                | N/A - separate PowerShell script
                New-ExtenderRightHashTable             | N/A - separate PowerShell script
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

        #Create a hashtable to store the GUID value of each schema class and attribute
        $guidmap = New-GuidObjectHashTable

        #Create a hashtable for Extended Rights GUID
        $extendedrightsmap = New-ExtenderRightHashTable

        $parameters = $null

        # Get Corresponding context
        [string]$DefaultNamingContext = ([ADSI]'LDAP://RootDSE').rootDomainNamingContext
    }
    Process {

        ####################
        # Add/remove replica in domain
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = $DefaultNamingContext
            AdRight               = 'ExtendedRight'
            AccessControlType     = 'Allow'
            ObjectType            = $extendedrightsmap['Add/remove replica in domain']
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor4 @parameters

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

        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,CN=Configuration,{0}' -f $DefaultNamingContext
            AdRight               = 'CreateChild'
            AccessControlType     = 'Allow'
            ObjectType            = $guidmap['nTDSDSA']
            AdSecurityInheritance = 'Descendents'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters

        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,CN=Configuration,{0}' -f $DefaultNamingContext
            AdRight               = 'WriteDacl'
            AccessControlType     = 'Allow'
            ObjectType            = $guidmap['nTDSDSA']
            AdSecurityInheritance = 'Descendents'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters

        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,CN=Configuration,{0}' -f $DefaultNamingContext
            AdRight               = 'CreateChild'
            AccessControlType     = 'Allow'
            ObjectType            = $guidmap['server']
            AdSecurityInheritance = 'Descendents'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters

        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=Sites,CN=Configuration,{0}' -f $DefaultNamingContext
            AdRight               = 'CreateChild'
            AccessControlType     = 'Allow'
            ObjectType            = $guidmap['nTDSConnection']
            AdSecurityInheritance = 'Descendents'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters


        ####################
        # Prepare Staging container for to-be-promoted server
        If($StagingOU) {
            $existingOU = Get-ADOrganizationalUnit -Filter { DistinguishedName -like $StagingOU } -ErrorAction SilentlyContinue

            If(-not($existingOU)) {
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
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
} #end Function Set-AdAclPromoteDomain

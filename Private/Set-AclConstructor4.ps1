# Constructor W/4 attributes https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=dotnet-plat-ext-6.0#system-directoryservices-activedirectoryaccessrule-ctor(system-security-principal-identityreference-system-directoryservices-activedirectoryrights-system-security-accesscontrol-accesscontroltype-system-directoryservices-activedirectorysecurityinheritance)

function Set-AclConstructor4 {
    <#
        .Synopsis
            Helper function calling the AdAccessRule constructor using the corresponding 4 attributes
        .EXAMPLE
            Set-AclConstructor4 -Id "SG_SiteAdmins_XXXX" `
            -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" `
            -AdRight "CreateChild,DeleteChild" `
            -AccessControlType "Allow" `
            -ObjectType 12345678-abcd-1234-abcd-0123456789012
        .EXAMPLE
            $splat = @{
                Id                = "SG_SiteAdmins_XXXX" `
                LDAPPath          = "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" `
                AdRight           = "CreateChild,DeleteChild" `
                AccessControlType = "Allow" `
                ObjectType        = "12345678-abcd-1234-abcd-0123456789012"
            }
            Set-AclConstructor4 @Splat
        .PARAMETER ID
            [String] Identity of the Delegated Group
        .PARAMETER LDAPPath
            [String] Distinguished Name of the object
        .PARAMETER AdRight
            [String] Active Directory Rights
        .PARAMETER AccessControlType
            [String] Allow or Deny access to the given object
        .PARAMETER ObjectType
            [GUID] of the object
        .PARAMETER RemoveRule
            [Switch] togle between ADD or REMOVE the rule
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-ADObject                           | ActiveDirectory
                Get-Acl                                | Microsoft.Powershell.Security
                Set-Acl                                | Microsoft.Powershell.Security
                New-Object                             | Microsoft.Powershell.Utility
                Set-Location                           | Microsoft.Powershell.Management
        .NOTES
            Version:         1.0
            DateModified:    28/Apr/2022
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]

    param (
        # PARAM1 STRING for the Delegated Identity
        # An IdentityReference object that identifies the trustee of the access rule.
        [Parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ValueFromRemainingArguments=$false,
            HelpMessage = 'SamAccountName of the Delegated Group. An IdentityReference object that identifies the trustee of the access rule.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference','Identity','Trustee','GroupID')]
        [String]
        $Id,

        # PARAM2 STRING for the object's LDAP path
        # The LDAP path to the object where the ACL will be changed
        [Parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ValueFromRemainingArguments=$false,
            HelpMessage = 'Distinguished (DN) Name of the object. The LDAP path to the object where the ACL will be changed.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('DN','DistinguishedName')]
        [String]
        $LDAPpath,

        # PARAM3 STRING representing AdRight
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Active Directory Right',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('CreateChild', 'DeleteChild', 'Delete', 'DeleteTree', 'ExtendedRight', 'GenericAll', 'GenericExecute', 'GenericRead', 'GenericWrite', 'ListChildren', 'ListObject', 'ReadControl', 'ReadProperty', 'Self', 'Synchronize', 'WriteDacl', 'WriteOwner', 'WriteProperty')]
        [Alias('ActiveDirectoryRights')]
        [String[]]
        $AdRight,

        # PARAM4 STRING representing Access Control Type
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Allow or Deny access to the given object',
            Position = 3)]
        [ValidateSet('Allow', 'Deny')]
        [String]
        $AccessControlType,

        # PARAM5 STRING representing Object GUID
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Schema GUID of the affected object, either object or Extended Right.',
            Position = 4)]
        [AllowNull()]
        [Guid]
        $ObjectType,

        # PARAM6 SWITCH if $false (default) will add the rule. If $true, it will remove the rule
        [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 5)]
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



        $groupObject, $groupSID, $acl, $trustee, $AdRight, $AccessControlType, $ObjectType, $RuleArguments = $null
        $IsWellKnownSid = $null

        # Check if the guidmap variable is empty and fill it if required
        #New-GuidObjectHashTable

        # Check if the guidmap variable is empty and fill it if required
        #New-ExtenderRightHashTable

        Set-Location -Path AD:\
    } #end Begin

    Process {
        # Collect the SID for the trustee we will be delegating to
        $groupObject = Get-ADGroup -Identity $PSBoundParameters['Id']

        # Check if Identity is a WellKnownSID
        # If identity is NOT a WellKnownSID, the function will translate to existing Object SID.
        # WellKnownSid function will return null if SID is not well known.
        $IsWellKnownSid = Get-AdWellKnownSid -Sid $groupObject.SID

        If(-not $IsWellKnownSid) {
            # translate to existing Object SID
            $groupSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $groupObject.SID
        } else {
            $groupSID = $IsWellKnownSid.value
        }

        try {
            #Get a reference to the Object we want to delegate
            $object = Get-ADObject -Identity $PSBoundParameters['LDAPPath']

            #Get a copy of the current DACL on the object
            $acl = Get-Acl -Path ($object.DistinguishedName)

            # Start creating the Access Rule Arguments
            #  Provide the trustee identity (Group who gets the permissions)
            $trustee = [Security.Principal.IdentityReference] $groupSID

            # Set what to do (AD Rights http://msdn.microsoft.com/en-us/library/system.directoryservices.activedirectoryrights(v=vs.110).aspx)
            $AdRight = [DirectoryServices.ActiveDirectoryRights] $PSBoundParameters['AdRight']

            # Define if allowed or denied (AccessControlType - Allow/Denied)
            $AccessControlType = [Security.AccessControl.AccessControlType] $PSBoundParameters['AccessControlType']

            # Set the object GUID
            $ObjectType = $PSBoundParameters['ObjectType']

            $RuleArguments = $trustee, $AdRight, $AccessControlType, $ObjectType

            # If parameter RemoveRule is False (default when omitted) it will ADD the Access Rule
            # if TRUE then will REMOVE the access rule
            If ($PSBoundParameters['RemoveRule']) {
                # Action when TRUE is REMOVE
                #Create an Access Control Entry for new permission we wish to remove
                $null = $acl.RemoveAccessRule((New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $RuleArguments))
            } else {
                # Action when FALSE is ADD
                #Create an Access Control Entry for new permission we wish to add
                $null = $acl.AddAccessRule((New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $RuleArguments))
            }

            #Re-apply the modified DACL to the OU
            Set-Acl -AclObject $acl -Path ('AD:\{0}' -f $object.DistinguishedName)
        } Catch { throw  }
    } #end Process

    End {
        Set-Location -Path $env:HOMEDRIVE\

        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
} #end Function Set-AclConstructor4

# Constructor W/4 attributes https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=dotnet-plat-ext-6.0#system-directoryservices-activedirectoryaccessrule-ctor(system-security-principal-identityreference-system-directoryservices-activedirectoryrights-system-security-accesscontrol-accesscontroltype-system-directoryservices-activedirectorysecurityinheritance)

function Set-AclConstructor4 {
    <#
        .SYNOPSIS
        Modifies ACLs on Active Directory objects.

        .DESCRIPTION
            This function adds or removes access rules to an Active Directory object
            using a constructor with four parameters to specify the access rule details.

        .PARAMETER Id
            Specifies the SamAccountName of the delegated group or user. This is the identity for which the access rule will be modified.
            It can be a variable containing the AD group.

        .PARAMETER LDAPPath
            Specifies the LDAP path of the target Active Directory object.

        .PARAMETER AdRight
            Specifies the Active Directory rights. Valid options include CreateChild, DeleteChild, and others.

        .PARAMETER AccessControlType
            Specifies whether the access control is to Allow or Deny.

        .PARAMETER ObjectType
            Specifies the object type GUID. Use for specific property access or extended rights.

        .PARAMETER RemoveRule
            If specified, the access rule will be removed. If omitted, the access rule will be added.

        .EXAMPLE
            Set-AclConstructor4 -Id "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -AdRight "CreateChild,DeleteChild" -AccessControlType "Allow" -ObjectType "12345678-abcd-1234-abcd-0123456789012"

        .EXAMPLE
            $splat = @{
                Id                = "SG_SiteAdmins_XXXX"
                LDAPPath          = "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
                AdRight           = "CreateChild,DeleteChild"
                AccessControlType = "Allow"
                ObjectType        = "12345678-abcd-1234-abcd-0123456789012"
            }
            Set-AclConstructor4 @splat

        .EXAMPLE
            $group = Get-AdGroup "SG_SiteAdmins_XXXX"

            $splat = @{
                Id                = $group
                LDAPPath          = "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
                AdRight           = "CreateChild,DeleteChild"
                AccessControlType = "Allow"
                ObjectType        = "12345678-abcd-1234-abcd-0123456789012"
            }
            Set-AclConstructor4 @splat

        .INPUTS
            String, GUID

        .OUTPUTS
            None. Modifies Active Directory object ACLs.

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-ADObject                           | ActiveDirectory
                Get-Acl                                | Microsoft.Powershell.Security
                Set-Acl                                | Microsoft.Powershell.Security
                New-Object                             | Microsoft.Powershell.Utility
                Set-Location                           | Microsoft.Powershell.Management
                Get-AdObjectType                       | EguibarIT.DelegationPS
                Test-IsValidDN                         | EguibarIT.DelegationPS
                Get-CurrentErrorToDisplay              | EguibarIT.DelegationPS
        .NOTES
            Version:         1.1
            DateModified:    08/Feb/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([void])]

    param (
        # PARAM1 STRING for the Delegated Identity
        # An IdentityReference object that identifies the trustee of the access rule.
        [Parameter(Mandatory = $true, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'SamAccountName of the Delegated Group (It also valid variable containing the group). An IdentityReference object that identifies the trustee of the access rule.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID', 'Group')]
        $Id,

        # PARAM2 STRING for the object's LDAP path
        # The LDAP path to the object where the ACL will be changed
        [Parameter(Mandatory = $true, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Distinguished (DN) Name of the object. The LDAP path to the object where the ACL will be changed.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        # PARAM3 STRING representing AdRight
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Active Directory Right',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        #[ValidateScript({ [ActiveDirectoryRights]::new().GetValidValues().Contains($_) })]
        #[ValidateSet('CreateChild', 'DeleteChild', 'Delete', 'DeleteTree', 'ExtendedRight', 'GenericAll', 'GenericExecute', 'GenericRead', 'GenericWrite', 'ListChildren', 'ListObject', 'ReadControl', 'ReadProperty', 'Self', 'Synchronize', 'WriteDacl', 'WriteOwner', 'WriteProperty')]
        [ValidateSet([ActiveDirectoryRights])]
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

        $groupObject, $groupSID, $acl, $trustee, $RuleArguments = $null

    } #end Begin

    Process {

        # Collect the SID for the trustee we will be delegating to.
        # NULL will be returned if ID is a WellKnownSid
        If (-not ($PSBoundParameters['Id'] -is [Microsoft.ActiveDirectory.Management.AdGroup])) {
            $GroupObject = Get-AdObjectType -Identity $PSBoundParameters['Id']
        }

        # $groupObject will be NULL if ID is a WellKnownSid
        If ($null -eq $GroupObject) {

            # Check if Identity is a WellKnownSID
            If ($WellKnownSIDs.ContainsKey($PSBoundParameters['Id'])) {
                $groupSID = $PSBoundParameters['Id']
            }
        } else {
            # If identity is NOT a WellKnownSID, the function will translate to existing Object SID.
            $groupSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $groupObject.SID
        }


        #Get a reference to the Object we want to delegate
        If (Test-IsValidDN -ObjectDN $PSBoundParameters['LDAPPath']) {
            try {
                $object = Get-ADObject -Identity $PSBoundParameters['LDAPPath']
            } Catch {
                Get-CurrentErrorToDisplay -CurrentError $error[0]
            } #end Try-Catch
        }


        #Get a copy of the current DACL on the object
        try {
            $acl = Get-Acl -Path ('AD:\{0}' -f $object.DistinguishedName)
        } Catch {
            Get-CurrentErrorToDisplay -CurrentError $error[0]
        } #end Try-Catch


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
            [void]$acl.RemoveAccessRule((New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $RuleArguments))
            Write-Verbose -Message ('Removed access rule from {0}' -f $objectDN.DistinguishedName)

        } else {
            # Action when FALSE is ADD
            #Create an Access Control Entry for new permission we wish to add
            [void]$acl.AddAccessRule((New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $RuleArguments))
            Write-Verbose -Message ('Added access rule to {0}' -f $objectDN.DistinguishedName)
        } #end If-Else

        try {
            #Re-apply the modified DACL to the OU
            Set-Acl -AclObject $acl -Path ('AD:\{0}' -f $object.DistinguishedName)
        } Catch {
            Get-CurrentErrorToDisplay -CurrentError $error[0]
            throw
        } #end Try-Catch
    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
} #end Function Set-AclConstructor4

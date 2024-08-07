# Constructor W/5 attributes https://msdn.microsoft.com/en-us/library/cawwkf0x.aspx

function Set-AclConstructor5 {
    <#
        .Synopsis
        Modifies ACLs on Active Directory objects.

        .DESCRIPTION
            This function adds or removes access rules to an Active Directory object
            using a constructor with 5 parameters to specify the access rule details.

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

        .PARAMETER AdSecurityInheritance
            Security inheritance of the new right (All, Children, Descendent, None, SelfAndChildren)

        .EXAMPLE
            Set-AclConstructor5 -Id "SG_SiteAdmins_XXXX"
            -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
            -AdRight "CreateChild,DeleteChild"
            -AccessControlType "Allow"
            -ObjectType 12345678-abcd-1234-abcd-0123456789012
            -AdSecurityInheritance "All"

        .EXAMPLE
            $Splat = @{
                Id                    = "SG_SiteAdmins_XXXX"
                LDAPPath              = "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
                AdRight               = "CreateChild,DeleteChild"
                AccessControlType     = "Allow"
                ObjectType            = '12345678-abcd-1234-abcd-0123456789012'
                AdSecurityInheritance = "All"
            }
            Set-AclConstructor5 @Splat

        .EXAMPLE
            $group = Get-AdGroup "SG_SiteAdmins_XXXX"

            $Splat = @{
                Id                    = $group
                LDAPPath              = "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
                AdRight               = "CreateChild,DeleteChild"
                AccessControlType     = "Allow"
                ObjectType            = '12345678-abcd-1234-abcd-0123456789012'
                AdSecurityInheritance = "All"
            }
            Set-AclConstructor5 @Splat

        .NOTES
                Used Functions:
                    Name                                   | Module
                    ---------------------------------------|--------------------------
                    Get-ADObject                           | ActiveDirectory
                    Get-Acl                                | Microsoft.Powershell.Security
                    Set-Acl                                | Microsoft.Powershell.Security
                    New-Object                             | Microsoft.Powershell.Utility
                    Get-AdObjectType                       | EguibarIT.DelegationPS
                    Test-IsValidDN                         | EguibarIT.DelegationPS
                    Get-CurrentErrorToDisplay              | EguibarIT.DelegationPS

        .NOTES
        Version:         2.0
        DateModified:    09/Feb/2024
        LasModifiedBy:   Vicente Rodriguez Eguibar
            vicente@eguibar.com
            Eguibar Information Technology S.L.
            http://www.eguibarit.com
  #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([void])]

    param (
        # PARAM1 STRING for the Delegated Identity
        # An IdentityReference object that identifies the trustee of the access rule.
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the Delegated Group',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID', 'Group')]
        $Id,

        # PARAM2 STRING for the object's LDAP path
        # The LDAP path to the object where the ACL will be changed
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the object',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ })]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        # PARAM3 STRING representing AdRight
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Active Directory Right',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet([ActiveDirectoryRights])]
        [Alias('ActiveDirectoryRights')]
        [String[]]
        $AdRight,

        # PARAM4 STRING representing Access Control Type
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Allow or Deny access to the given object',
            Position = 3)]
        #[ValidateSet('Allow', 'Deny')]
        [ValidateSet([AccessControlType])]
        [String]
        $AccessControlType,

        # PARAM5 STRING representing Object GUID
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'GUID of the object',
            Position = 4)]
        [AllowNull()]
        [Guid]
        $ObjectType,

        # PARAM6 STRING representing ActiveDirectory Security Inheritance
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Security inheritance of the new right (All, Children, Descendents, None, SelfAndChildren)',
            Position = 5)]
        #[ValidateSet('All', 'Children', 'Descendents', 'None', 'SelfAndChildren')]
        [ValidateSet([ActiveDirectorySecurityInheritance], ErrorMessage = "Value '{0}' is invalid. Try one of: {1}")]
        [Alias('InheritanceType', 'ActiveDirectorySecurityInheritance')]
        [String]
        $AdSecurityInheritance,

        # PARAM7 SWITCH if $false (default) will add the rule. If $true, it will remove the rule
        [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 6)]
        [Switch]
        $RemoveRule
    )

    Begin {
        $txt = ($constants.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        $groupObject, $groupSID, $TmpSid, $acl, $Arg1, $Arg2, $Arg3, $Arg4, $Arg5, $RuleArguments = $null

    } #end Begin

    Process {

        # Collect the SID for the trustee we will be delegating to.
        # NULL will be returned if ID is a WellKnownSid
        #
        # Check if Identity is a WellKnownSID
        # Looking in var $Variables.WellKnownSIDs by Value (ej. 'authenticated users')
        # must be in lowercase to work
        If ($Variables.WellKnownSIDs.Values -Contains $PSBoundParameters['Id']) {

            # return SID of the WellKnownSid
            #$groupSID = $Variables.WellKnownSIDs.keys.where{ $Variables.WellKnownSIDs[$_].Contains($Id) }
            $TmpSid = ($Variables.WellKnownSIDs.GetEnumerator() | Where-Object { $_.value -eq $PSBoundParameters['Id'] }).Name

            $groupSID = [System.Security.Principal.SecurityIdentifier]::New($TmpSid)

            Write-Verbose -Message 'Identity is Well-Known SID. Retrieving the Well-Known SID'
        } else {
            $GroupObject = Get-AdObjectType -Identity $PSBoundParameters['Id']

            Write-Verbose -Message 'Identity is already a Group Object. Retrieving the Group'
        }

        # $groupObject will be NULL if ID is a WellKnownSid
        If ($null -ne $GroupObject) {

            # If identity is NOT a WellKnownSID, the function will translate to existing Object SID.
            $groupSID = [System.Security.Principal.SecurityIdentifier]::New($groupObject.SID)

            Write-Verbose -Message 'Retrieving SID of Identity'
        }

        #Get a reference to the Object we want to delegate
        try {

            #
            $object = Get-ADObject -Identity $PSBoundParameters['LDAPPath']

            Write-Verbose -Message ('Accessing the object from given LdapPath {0}.' -f $PSBoundParameters['LDAPPath'])

        } Catch {
            Write-Error -Message ('Error while trying to access LDAP object {0}' -f $PSBoundParameters['LDAPPath'])
            ## Get-CurrentErrorToDisplay -CurrentError $error[0]
            throw
        } #end Try-Catch


        #Get a copy of the current DACL on the object
        try {
            $acl = Get-Acl -Path ('AD:\{0}' -f $object.DistinguishedName)

            Write-Verbose -Message ('Get a copy of the current DACL on the object DN {0}.' -f $object.DistinguishedName)

        } Catch {
            Write-Error -Message ('Error while trying to Get a copy of the current DACL {0}' -f $object.DistinguishedName)
            ## Get-CurrentErrorToDisplay -CurrentError $error[0]
            throw
        } #end Try-Catch




        # Start creating the Access Rule Arguments
        #  Provide the trustee identity (Group who gets the permissions)
        $Arg1 = [Security.Principal.IdentityReference] $groupSID


        # Set what to do (AD Rights http://msdn.microsoft.com/en-us/library/system.directoryservices.activedirectoryrights(v=vs.110).aspx)
        $Arg2 = [DirectoryServices.ActiveDirectoryRights] $PSBoundParameters['AdRight']

        # Define if allowed or denied (AccessControlType - Allow/Denied)
        $Arg3 = [Security.AccessControl.AccessControlType] $PSBoundParameters['AccessControlType']

        # Set the object GUID
        $Arg4 = $PSBoundParameters['ObjectType']

        # Set the scope (AdSecurityInheritance - http://msdn.microsoft.com/en-us/library/system.directoryservices.activedirectorysecurityinheritance(v=vs.110).aspx)
        $Arg5 = [DirectoryServices.ActiveDirectorySecurityInheritance] $PSBoundParameters['AdSecurityInheritance']

        $RuleArguments = $Arg1, $Arg2, $Arg3, $Arg4, $Arg5



        # If parameter RemoveRule is False (default when omitted) it will ADD the Access Rule
        # if TRUE then will REMOVE the access rule
        If ($PSBoundParameters['RemoveRule']) {
            # Action when TRUE is REMOVE

            if ($Force -or $PSCmdlet.ShouldProcess($object.DistinguishedName, "Removing access rule for $($PSBoundParameters['Id'])")) {

                #Create an Access Control Entry for new permission we wish to remove
                $null = $acl.RemoveAccessRule(([System.DirectoryServices.ActiveDirectoryAccessRule]::New($Arg1, $Arg2, $Arg3, $Arg4, $Arg5)))

                Write-Verbose -Message ('Removed access rule from {0}' -f $objectDN.DistinguishedName)
            } #end If
        } else {
            # Action when FALSE is ADD

            if ($Force -or $PSCmdlet.ShouldProcess($object.DistinguishedName, "Adding access rule for $($PSBoundParameters['Id'])")) {

                #Create an Access Control Entry for new permission we wish to add
                [void]$acl.AddAccessRule(([System.DirectoryServices.ActiveDirectoryAccessRule]::New($Arg1, $Arg2, $Arg3, $Arg4, $Arg5)))
                #$null = $acl.AddAccessRule((New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $RuleArguments))

                Write-Verbose -Message ('Added access rule to {0}' -f $objectDN.DistinguishedName)
            } #end If
        } #end If-Else



        try {
            #Re-apply the modified DACL to the OU
            Set-Acl -AclObject $acl -Path ('AD:\{0}' -f $object.DistinguishedName)

            Write-Verbose -Message ('Re-apply the modified DACL to the {0}' -f $objectDN.DistinguishedName)

        } Catch {
            Write-Error -Message ('Error when trying to re-apply the modified DACL to the {0}' -f $objectDN.DistinguishedName)
            ## Get-CurrentErrorToDisplay -CurrentError $error[0]
            throw
        } #end Try-Catch

    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished adding access rule with 5 arguments."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}

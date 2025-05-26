function Set-AclConstructor4 {
    <#
        .SYNOPSIS
            Modifies ACLs on Active Directory objects using a 4-parameter constructor.

        .DESCRIPTION
            This function adds or removes access control entries (ACEs) on Active Directory objects
            using the ActiveDirectoryAccessRule constructor with 4 parameters:
            - Identity Reference
            - Active Directory Rights
            - Access Control Type
            - Object Type GUID

            The function provides granular control over permissions by allowing you to specify
            precise object types (schema GUIDs) for operations. It is optimized for large AD
            environments through efficient error handling and validation.

            This constructor is particularly useful when you need to apply permissions to specific
            object types or attributes in AD, rather than to all objects or properties.

        .PARAMETER Id
            Specifies the security principal (user, group, computer) that will receive the permission.
            This parameter accepts:
            - String: SamAccountName of the delegated group or user
            - AD object: Variable containing an AD user or group object
            - SID: Security Identifier object or string

        .PARAMETER LDAPPath
            Specifies the LDAP path (Distinguished Name) of the target Active Directory object
            on which the permissions will be set. This must be a valid LDAP path in the domain.

        .PARAMETER AdRight
            Specifies the Active Directory rights to assign. This parameter accepts multiple values
            separated by commas. Valid values include:
            - CreateChild
            - DeleteChild
            - ListChildren
            - Self
            - ReadProperty
            - WriteProperty
            - DeleteTree
            - ListObject
            - ExtendedRight
            - Delete
            - ReadControl
            - GenericExecute
            - GenericWrite
            - GenericRead
            - WriteDacl
            - WriteOwner
            - GenericAll
            - Synchronize
            - AccessSystemSecurity

        .PARAMETER AccessControlType
            Specifies whether to Allow or Deny the permission. Valid values are:
            - Allow
            - Deny

        .PARAMETER ObjectType
            Specifies the object type GUID that defines the type of object the permission applies to.
            This can be:
            - Property set GUID
            - Extended right GUID
            - Object class GUID

            Object type GUIDs determine the specific attributes or operations the permission applies to.

        .PARAMETER RemoveRule
            If specified, the access rule will be removed instead of added.
            By default, the function adds the specified permission.

        .EXAMPLE
            Set-AclConstructor4 -Id "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -AdRight "CreateChild,DeleteChild" -AccessControlType "Allow" -ObjectType "bf967aba-0de6-11d0-a285-00aa003049e2"

            Adds permission for the SG_SiteAdmins_XXXX group to create and delete user objects
            (specified by the user class GUID) in the Users OU.

        .EXAMPLE
            $splat = @{
                Id                = "SG_SiteAdmins_XXXX"
                LDAPPath          = "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
                AdRight           = "ReadProperty,WriteProperty"
                AccessControlType = "Allow"
                ObjectType        = "bf967a9c-0de6-11d0-a285-00aa003049e2"
            }
            Set-AclConstructor4 @splat

            Adds permission for the SG_SiteAdmins_XXXX group to read and write the telephone number
            attribute (specified by the attribute GUID) for objects in the Users OU.

        .EXAMPLE
            $group = Get-AdGroup "SG_SiteAdmins_XXXX"

            $splat = @{
                Id                = $group
                LDAPPath          = "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
                AdRight           = "ExtendedRight"
                AccessControlType = "Allow"
                ObjectType        = "00299570-246d-11d0-a768-00aa006e0529"
                RemoveRule        = $true
            }
            Set-AclConstructor4 @splat

            Removes the extended right permission (Reset Password) for the SG_SiteAdmins_XXXX group
            on the Users OU.

        .INPUTS
            None. You cannot pipe objects to this function.

        .OUTPUTS
            System.Void

            This function does not return any objects. It modifies ACLs directly
            on Active Directory objects.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Get-ADObject                               ║ ActiveDirectory
                Get-Acl                                    ║ Microsoft.PowerShell.Security
                Set-Acl                                    ║ Microsoft.PowerShell.Security
                Test-IsValidDN                             ║ EguibarIT.DelegationPS
                Get-AdObjectType                           ║ EguibarIT.DelegationPS
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Write-Debug                                ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                        ║ EguibarIT.DelegationPS

        .NOTES
            Version:         4.0
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS

        .LINK
            https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=windowsdesktop-9.0#system-directoryservices-activedirectoryaccessrule-ctor(system-security-principal-identityreference-system-directoryservices-activedirectoryrights-system-security-accesscontrol-accesscontroltype-system-guid)

        .COMPONENT
            Active Directory

        .ROLE
            Security Administration

        .FUNCTIONALITY
            Access Control Management

        .FUNCTIONALITY
            Active Directory ACL Management
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Low',
        DefaultParameterSetName = 'Default',
        PositionalBinding = $true
    )]
    [OutputType([void])]

    param (
        # PARAM1 STRING for the Delegated Identity
        # An IdentityReference object that identifies the trustee of the access rule.
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'SamAccountName of the Delegated Group (It also valid variable containing the group). An IdentityReference object that identifies the trustee of the access rule.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID', 'Group')]
        $Id,

        # PARAM2 STRING for the object's LDAP path
        # The LDAP path to the object where the ACL will be changed
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Distinguished (DN) Name of the object. The LDAP path to the object where the ACL will be changed.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            { Test-IsValidDN -ObjectDN $_ },
            ErrorMessage = 'DistinguishedName provided is not valid! Please Check.'
        )]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        # PARAM3 STRING representing AdRight
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Active Directory Right',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet([ActiveDirectoryRights])]
        [Alias('ActiveDirectoryRights')]
        [String[]]
        $AdRight,

        # PARAM4 STRING representing Access Control Type
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Allow or Deny access to the given object',
            Position = 3)]
        #[ValidateSet('Allow', 'Deny')]
        [ValidateSet([AccessControlType])]
        [String]
        $AccessControlType,

        # PARAM5 STRING representing Object GUID
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Schema GUID of the affected object, either object or Extended Right.',
            Position = 4)]
        [AllowNull()]
        $ObjectType,

        # PARAM6 SWITCH if $false (default) will add the rule. If $true, it will remove the rule
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 5)]
        [Switch]
        $RemoveRule
    )

    Begin {

        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.HeaderDelegation) {

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

        [System.Security.Principal.SecurityIdentifier]$GroupSid = $null
        [System.DirectoryServices.ActiveDirectoryAccessRule]$AccessRule = $null
        [String]$ObjectPath = $null
        [Bool]$IsWellKnownSid = $false
        [HashTable]$AdObjectCache = @{}
        [int]$RulesRemovedCount = 0

        # Convert ObjectType to GUID if it's a string
        if ($null -ne $PSBoundParameters['ObjectType']) {

            if ($PSBoundParameters['ObjectType'] -is [System.String]) {

                try {

                    $ObjectTypeGuid = [Guid]::Parse($PSBoundParameters['ObjectType'])

                    Write-Debug -Message (
                        'Successfully parsed ObjectType string to GUID: {0}' -f
                        $ObjectTypeGuid
                    )

                } catch {

                    Write-Error -Message (
                        'Failed to parse ObjectType as GUID: {0}' -f
                        $PSBoundParameters['ObjectType']
                    )
                    throw

                } #end try-catch

            } elseif ($PSBoundParameters['ObjectType'] -is [Guid]) {

                $ObjectTypeGuid = $PSBoundParameters['ObjectType']
                Write-Debug -Message ('Using provided ObjectType GUID: {0}' -f $ObjectTypeGuid)

            } #end if-elseif

        } #end if

    } #end Begin

    Process {

        try {
            #############################
            # Identify and resolve the trustee
            #############################

            # Check if Identity is a Well-Known SID
            if ($null -ne $Variables -and
                $null -ne $Variables.WellKnownSIDs -and
                $Variables.WellKnownSIDs.Values -contains $Id) {

                # Find and create SID for well-known identity
                $TmpSid = ($Variables.WellKnownSIDs.GetEnumerator() | Where-Object { $_.Value -eq $Id }).Name

                if ($null -ne $TmpSid) {

                    $GroupSid = [System.Security.Principal.SecurityIdentifier]::new($TmpSid)
                    $IsWellKnownSid = $true

                    Write-Debug -Message ('Identity {0} is a Well-Known SID. Retrieved SID: {1}' -f $Id, $GroupSid.Value)

                } else {

                    Write-Error -Message ('Well-known identity {0} found but unable to resolve SID' -f $Id)
                    return

                } #end if-else

            } else {

                # Get object information for the identity
                try {

                    $GroupObject = Get-AdObjectType -Identity $Id

                    if ($null -ne $GroupObject -and
                        $null -ne $GroupObject.SID) {

                        $GroupSid = [System.Security.Principal.SecurityIdentifier]::new($GroupObject.SID)

                        Write-Debug -Message ('Resolved identity {0} to SID: {1}' -f $Id, $GroupSid.Value)

                    } else {

                        Write-Error -Message ('Failed to resolve identity {0} to a valid security principal' -f $Id)
                        return

                    } #end if-else

                } catch {

                    Write-Error -Message ('Error resolving identity {0}: {1}' -f $Id, $_.Exception.Message)
                    throw

                } #end try-catch
            } #end if-else

            #############################
            # Get reference to target object
            #############################
            try {

                # Use caching to avoid redundant queries
                if ($AdObjectCache.ContainsKey($LDAPPath)) {

                    $Object = $AdObjectCache[$LDAPPath]

                    Write-Debug -Message ('Using cached object for LDAP path: {0}' -f $LDAPPath)

                } else {

                    # Use server-side filtering for better performance
                    $Object = Get-ADObject -Identity $LDAPPath -Properties nTSecurityDescriptor

                    $AdObjectCache[$LDAPPath] = $Object

                    Write-Debug -Message ('Retrieved object from AD: {0}' -f $Object.DistinguishedName)

                } #end if-else

                # Prepare the AD path for Get-Acl
                $ObjectPath = ('AD:\{0}' -f $Object.DistinguishedName)

            } catch {

                Write-Error -Message ('Error retrieving AD object {0}: {1}' -f $LDAPPath, $_.Exception.Message)
                throw

            } #end try-catch

            #############################
            # Get current ACL
            #############################
            try {

                $Acl = Get-Acl -Path $ObjectPath

                Write-Debug -Message ('Retrieved current DACL for object: {0}' -f $Object.DistinguishedName)

            } catch {

                Write-Error -Message ('Error retrieving ACL for {0}: {1}' -f $Object.DistinguishedName, $_.Exception.Message)
                throw

            } #end try-catch


            #############################
            # Prepare access rule arguments
            #############################
            # 1. Identity Reference (Trustee)
            $IdentityRef = [System.Security.Principal.IdentityReference]$GroupSid

            # 2. Active Directory Rights
            $ActiveDirectoryRight = [System.DirectoryServices.ActiveDirectoryRights]$PSBoundParameters['AdRight']

            # 3. Access Control Type (Allow/Deny)
            $ACType = [System.Security.AccessControl.AccessControlType]$PSBoundParameters['AccessControlType']

            # 4. Object Type (GUID)
            # Parameter already properly typed as Guid


            # Create Access Rule object
            $AccessRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                $IdentityRef,
                $ActiveDirectoryRight,
                $ACType,
                $ObjectTypeGuid
            )

            #############################
            # Add or Remove the rule
            #############################
            if ($RemoveRule) {

                # Remove the access rule
                if ($PSCmdlet.ShouldProcess(
                        $Object.DistinguishedName,
                    ('Remove {0} access rule for {1}' -f $ActiveDirectoryRight, $Id))) {

                    # Find and remove matching rules
                    $RulesToRemove = $Acl.Access | Where-Object {
                        $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $GroupSid.Value -and
                        $_.ActiveDirectoryRights -eq $ActiveDirectoryRight -and
                        $_.AccessControlType -eq $ACType -and
                        $_.ObjectType -eq $ObjectTypeGuid
                    }

                    # Check if any rules were found
                    if ($null -ne $RulesToRemove) {
                        if ($RulesToRemove -is [array]) {
                            foreach ($RuleToRemove in $RulesToRemove) {
                                $null = $Acl.RemoveAccessRule($RuleToRemove)
                                $RulesRemovedCount++
                            } #end foreach
                        } else {
                            # Single object case
                            $null = $Acl.RemoveAccessRule($RulesToRemove)
                            $RulesRemovedCount = 1
                        }
                    } #end if

                    Write-Verbose -Message ('Removed {0} access rule(s) from {1} for {2}' -f
                        $RulesRemovedCount, $Object.DistinguishedName, $Id)
                } #end if

            } else {

                # Add the access rule
                if ($PSCmdlet.ShouldProcess(
                        $Object.DistinguishedName,
                    ('Add {0} access rule for {1}' -f $ActiveDirectoryRight, $Id))) {

                    $null = $Acl.AddAccessRule($AccessRule)

                    Write-Verbose -Message ('Added {0} access rule to {1} for {2}' -f
                        $ActiveDirectoryRight, $Object.DistinguishedName, $Id)
                } #end if

            } #end if-else

            #############################
            # Apply the modified ACL
            #############################
            try {

                if ($PSCmdlet.ShouldProcess(
                        $Object.DistinguishedName,
                        'Apply modified ACL')) {

                    try {
                        # Attempt to set ACL with standard method first
                        Set-Acl -AclObject $Acl -Path $ObjectPath -ErrorAction Stop
                        Write-Verbose -Message ('Applied modified ACL to {0}' -f $Object.DistinguishedName)
                    } catch [System.UnauthorizedAccessException] {
                        # Handle access denied errors by using a different approach
                        Write-Verbose -Message ('Access denied using Set-Acl. Attempting alternative method for {0}' -f $Object.DistinguishedName)

                        # Get the DirectoryEntry object directly
                        $DirectoryEntry = [ADSI]"LDAP://$($Object.DistinguishedName)"

                        # Set the security descriptor
                        $DirectoryEntry.psbase.ObjectSecurity = $Acl

                        # Commit the changes
                        $DirectoryEntry.psbase.CommitChanges()

                        Write-Verbose -Message ('Successfully applied ACL to {0} using DirectoryEntry method' -f $Object.DistinguishedName)
                    }

                } #end if

            } catch {

                Write-Error -Message ('
                    Error applying modified ACL to {0}: {1}
                    ' -f $Object.DistinguishedName, $_.Exception.Message
                )
                throw
            } #end try-catch

        } catch {

            Write-Error -Message ('Error processing {0}: {1}' -f $LDAPPath, $_.Exception.Message)
            Write-Error -Message $_.ScriptStackTrace
            throw

        } #end try-catch

    } #end Process

    End {
        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'adding access rule with 4 arguments (Private Function).'
            )
            Write-Verbose -Message $txt
        } #end if
    } #end End
} #end Function Set-AclConstructor4

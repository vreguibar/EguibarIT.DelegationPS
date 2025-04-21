function Set-AclConstructor5 {
    <#
        .SYNOPSIS
            Modifies ACLs (Access Control Lists) on Active Directory objects using a 5-parameter constructor.

        .DESCRIPTION
            The Set-AclConstructor5 function adds or removes access rules to/from Active Directory objects.
            It uses a constructor with 5 parameters to specify the access rule details.

            This function is designed for efficient permission management in Active Directory environments,
            supporting batch processing and optimized for large AD environments with 100k+ objects.

            The function can:
            - Add a new access rule to an object
            - Remove an existing access rule from an object
            - Handle various types of Active Directory rights
            - Apply permissions with different inheritance levels

        .PARAMETER Id
            Specifies the identity (SamAccountName, SID, or AD object) of the delegated group or user.
            This is the identity for which the access rule will be created or modified.
            It can be provided as a string containing the SamAccountName, a security principal object,
            or a variable containing an AD group/user.

            The function will resolve this to a SecurityIdentifier for use in the access rule.

        .PARAMETER LDAPPath
            Specifies the LDAP path (Distinguished Name) of the target Active Directory object.
            This is the object whose ACL will be modified.

            The path must be a valid Distinguished Name in the Active Directory environment.

        .PARAMETER AdRight
            Specifies the Active Directory rights to grant or deny.

            Valid options include:
            - CreateChild: Right to create child objects
            - DeleteChild: Right to delete child objects
            - ListContents: Right to list contents
            - Self: Right to manipulate attributes of the object itself
            - ReadProperty: Right to read properties
            - WriteProperty: Right to write properties
            - DeleteTree: Right to delete a tree of objects
            - Delete: Right to delete the object
            - GenericRead: Combination of standard read rights
            - GenericWrite: Combination of standard write rights
            - GenericAll: Full control rights
            - WriteDacl: Right to modify the DACL
            - WriteOwner: Right to change ownership
            - ReadControl: Right to read security information

            This parameter accepts multiple values as a comma-separated string array.

        .PARAMETER AccessControlType
            Specifies whether the access control is to Allow or Deny the specified rights.

            Valid values are:
            - Allow: Grants the specified permissions
            - Deny: Explicitly blocks the specified permissions

        .PARAMETER ObjectType
            Specifies the object type GUID to which the access rule applies.

            This parameter can be used to:
            - Target specific property sets (like Personal-Information)
            - Apply extended rights (like User-Force-Change-Password)
            - Restrict creation of specific object types

            Can be provided as a GUID string or a System.Guid object.
            For schema-wide applications, this can be set to null.

        .PARAMETER AdSecurityInheritance
            Specifies the security inheritance level of the new access rule.

            Valid values are:
            - All: The ACE is inherited by this object and all child objects
            - Children: The ACE is inherited by child objects but not by this object
            - Descendents: The ACE is inherited by all objects within the tree but not by this object
            - None: The ACE is not inherited by child objects
            - SelfAndChildren: The ACE is inherited by this object and its immediate children

        .PARAMETER RemoveRule
            If specified, the matching access rule will be removed instead of added.

            If omitted (default), the specified access rule will be added to the object.

            When removing rules, the function will match all parameters exactly to identify
            which rule(s) to remove.

        .EXAMPLE
            Set-AclConstructor5 -Id "SG_SiteAdmins_XXXX" `
                -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" `
                -AdRight "CreateChild,DeleteChild" `
                -AccessControlType "Allow" `
                -ObjectType "bf967aba-0de6-11d0-a285-00aa003049e2" `
                -AdSecurityInheritance "All"

            Description: This example grants the "SG_SiteAdmins_XXXX" group permission to create and delete
            User objects (specified by the ObjectType GUID) within the specified OU and all its child objects.

        .EXAMPLE
            $Splat = @{
                Id                    = "SG_SiteAdmins_XXXX"
                LDAPPath              = "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
                AdRight               = "CreateChild,DeleteChild"
                AccessControlType     = "Allow"
                ObjectType            = "bf967aba-0de6-11d0-a285-00aa003049e2"
                AdSecurityInheritance = "All"
            }
            Set-AclConstructor5 @Splat

            Description: This example demonstrates using splatting to pass parameters to the function,
            making the code more readable and maintainable, especially with multiple parameter sets.

        .EXAMPLE
            $group = Get-AdGroup "SG_SiteAdmins_XXXX"

            $Splat = @{
                Id                    = $group
                LDAPPath              = "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
                AdRight               = "ReadProperty,WriteProperty"
                AccessControlType     = "Allow"
                ObjectType            = "4c164200-20c0-11d0-a768-00aa006e0529"  # User Account Restrictions property set
                AdSecurityInheritance = "Descendents"
            }
            Set-AclConstructor5 @Splat

            Description: This example demonstrates using an AD group object directly as the identity,
            and granting read/write permissions to the "User Account Restrictions" property set
            (account lockout settings, etc.) for all descendant objects.

        .EXAMPLE
            $Splat = @{
                Id                    = "SG_SiteAdmins_XXXX"
                LDAPPath              = "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
                AdRight               = "GenericAll"
                AccessControlType     = "Allow"
                ObjectType            = $null
                AdSecurityInheritance = "All"
                RemoveRule            = $true
            }
            Set-AclConstructor5 @Splat

            Description: This example demonstrates removing a previously granted permission.
            It removes the "GenericAll" (Full Control) permission that was granted to the
            SG_SiteAdmins_XXXX group on the specified OU.

        .INPUTS
            [System.String]
            [Microsoft.ActiveDirectory.Management.ADGroup]
            [Microsoft.ActiveDirectory.Management.ADUser]

            You can pipe the Id and LDAPPath parameters to this function.

        .OUTPUTS
            [void]

            This function does not generate any output.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Get-ADObject                               ║ ActiveDirectory
                Get-Acl                                    ║ Microsoft.PowerShell.Security
                Set-Acl                                    ║ Microsoft.PowerShell.Security
                Test-IsValidDN                             ║ EguibarIT.DelegationPS
                Get-AdObjectType                           ║ EguibarIT.DelegationPS
                Get-FunctionDisplay                        ║ EguibarIT.DelegationPS
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Write-Debug                                ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         3.1
            DateModified:    12/Apr/2024
            LastModifiedBy:   Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Private/Set-AclConstructor5.ps1

        .LINK
            https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adobject
            https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl
            https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl
            https://msdn.microsoft.com/en-us/library/system.directoryservices.activedirectoryrights
            https://msdn.microsoft.com/en-us/library/system.directoryservices.activedirectorysecurityinheritance

        .COMPONENT
            Active Directory

        .ROLE
            Administrators

        .FUNCTIONALITY
            Active Directory, Security, Access Control, Delegation
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
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the Delegated Group',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID', 'Group')]
        $Id,

        # PARAM2 STRING for the object's LDAP path
        # The LDAP path to the object where the ACL will be changed
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the object',
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
            HelpMessage = 'GUID of the object',
            Position = 4)]
        [AllowNull()]
        $ObjectType,

        # PARAM6 STRING representing ActiveDirectory Security Inheritance
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Security inheritance of the new right (All, Children, Descendents, None, SelfAndChildren)',
            Position = 5)]
        [ValidateSet(
            [ActiveDirectorySecurityInheritance],
            ErrorMessage = "Value '{0}' is invalid. Try one of: {1}"
        )]
        [Alias('InheritanceType', 'ActiveDirectorySecurityInheritance')]
        [String]
        $AdSecurityInheritance,

        # PARAM7 SWITCH if $false (default) will add the rule. If $true, it will remove the rule
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 6)]
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

        # Convert ObjectType to GUID if it's a string
        if ($null -ne $PSBoundParameters['ObjectType']) {

            if ($PSBoundParameters['ObjectType'] -is [System.String]) {

                try {

                    $ObjectTypeGuid = [Guid]::Parse($PSBoundParameters['ObjectType'])
                    Write-Debug -Message ('Successfully parsed ObjectType string to GUID: {0}' -f $ObjectTypeGuid)

                } catch {

                    Write-Error -Message ('Failed to parse ObjectType as GUID: {0}' -f $PSBoundParameters['ObjectType'])
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

            # 5. Security Inheritance
            $SecurityInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]$PSBoundParameters['AdSecurityInheritance']

            # Create Access Rule object
            $AccessRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                $IdentityRef,
                $ActiveDirectoryRight,
                $ACType,
                $ObjectTypeGuid,
                $SecurityInheritance
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
                        $_.ObjectType -eq $ObjectTypeGuid -and
                        $_.InheritanceType -eq $SecurityInheritance
                    }

                    foreach ($RuleToRemove in $RulesToRemove) {

                        $null = $Acl.RemoveAccessRule($RuleToRemove)

                    } #end foreach

                    Write-Verbose -Message ('Removed {0} access rule(s) from {1} for {2}' -f
                        $RulesToRemove.Count, $Object.DistinguishedName, $Id)
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

                    Set-Acl -AclObject $Acl -Path $ObjectPath
                    Write-Verbose -Message ('Applied modified ACL to {0}' -f $Object.DistinguishedName)

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
                'adding access rule with 5 arguments (Private Function).'
            )
            Write-Verbose -Message $txt
        } #end if
    } #end END
} #end function Set-AclConstructor5

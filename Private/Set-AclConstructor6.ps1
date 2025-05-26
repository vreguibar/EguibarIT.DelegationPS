function Set-AclConstructor6 {
    <#
        .SYNOPSIS
            Modifies ACLs on Active Directory objects using a 6-parameter access rule constructor.

        .DESCRIPTION
            The Set-AclConstructor6 function adds or removes access rules to an Active Directory object
            using a constructor with 6 parameters to specify the access rule details. This specialized
            constructor form is used when you need to specify both ObjectType and InheritedObjectType GUIDs
            for granular permission control on specific object types within Active Directory.

            The function performs the following operations:
            1. Validates all input parameters
            2. Resolves the identity to its Security Identifier (SID)
            3. Retrieves the current access control list (ACL) of the target object
            4. Creates a new access rule using the 6-parameter constructor
            5. Adds or removes the access rule from the ACL
            6. Applies the modified ACL back to the target object

            It supports batch processing via pipeline input and is optimized for large AD environments
            by minimizing directory queries and using efficient parameter handling.

        .PARAMETER Id
            Specifies the identity (user or group) to which the permission will be granted or from which it will be removed.
            This can be provided as a SamAccountName, Distinguished Name, ObjectGUID, or as an Active Directory object.
            The function will resolve the identity to its SID automatically.

        .PARAMETER LDAPPath
            Specifies the LDAP path (Distinguished Name) of the target Active Directory object
            where the permissions will be modified. This must be a valid DN in the directory.

        .PARAMETER AdRight
            Specifies the Active Directory rights to grant or remove. This can be a single right or multiple rights combined.
            Valid values include: CreateChild, DeleteChild, ListChildren, Self, ReadProperty, WriteProperty, DeleteTree,
            ListObject, ExtendedRight, Delete, ReadControl, GenericExecute, GenericWrite, GenericRead, WriteDacl, WriteOwner,
            GenericAll, Synchronize, AccessSystemSecurity.

        .PARAMETER AccessControlType
            Specifies whether the access control is to Allow or Deny the specified permissions.
            Valid values are "Allow" and "Deny".

        .PARAMETER ObjectType
            Specifies the object type GUID that the access rule applies to. This can be:
            - A property set GUID
            - An extended right GUID
            - A validated write GUID
            - A property GUID
            - An object GUID

            Use this parameter when you need to control access to specific attributes or operations.
            Can be provided as a GUID string or a GUID object.

        .PARAMETER AdSecurityInheritance
            Specifies how the access rule is inherited by child objects.
            Valid values include:
            - "All": The access rule is inherited by this object and all child objects
            - "Descendents": The access rule is inherited by all child objects
            - "None": The access rule is not inherited
            - "SelfAndChildren": The access rule is inherited by the immediate child objects
            - "Children": The access rule is inherited only by child objects

        .PARAMETER InheritedObjectType
            Specifies the GUID of the object type that can inherit this access rule.
            This parameter is used to limit the inheritance to specific types of child objects.
            Can be provided as a GUID string or a GUID object.

        .PARAMETER RemoveRule
            If specified, the access rule will be removed instead of added.
            By default, the function adds the specified access rule.

        .EXAMPLE
            Set-AclConstructor6 -Id "SG_SiteAdmins_XXXX" `
                               -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" `
                               -AdRight "CreateChild,DeleteChild" `
                               -AccessControlType "Allow" `
                               -ObjectType "12345678-abcd-1234-abcd-0123456789012" `
                               -AdSecurityInheritance "All" `
                               -InheritedObjectType "12345678-abcd-1234-abcd-0123456789012"

            This example adds CreateChild and DeleteChild rights for the SG_SiteAdmins_XXXX group to the specified OU.
            The permissions apply to objects of the specified Object Type and are inherited by objects of the specified InheritedObjectType.

        .EXAMPLE
            $Splat = @{
                Id                    = "SG_SiteAdmins_XXXX"
                LDAPPath              = "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
                AdRight               = "CreateChild,DeleteChild"
                AccessControlType     = "Allow"
                ObjectType            = "12345678-abcd-1234-abcd-0123456789012"
                AdSecurityInheritance = "All"
                InheritedObjectType   = "87654321-dcba-4321-dcba-210987654321"
            }
            Set-AclConstructor6 @Splat

            This example uses splatting to provide the parameters for adding permissions.
            The permission will apply to the specified Object Type and be inherited by the specified InheritedObjectType.

        .EXAMPLE
            $group = Get-AdGroup "SG_SiteAdmins_XXXX"

            $Splat = @{
                Id                    = $group
                LDAPPath              = "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
                AdRight               = "CreateChild,DeleteChild"
                AccessControlType     = "Allow"
                ObjectType            = "12345678-abcd-1234-abcd-0123456789012"
                AdSecurityInheritance = "All"
                InheritedObjectType   = "87654321-dcba-4321-dcba-210987654321"
                RemoveRule            = $true
            }
            Set-AclConstructor6 @Splat

            This example removes CreateChild and DeleteChild rights from the specified OU for the SG_SiteAdmins_XXXX group.
            It demonstrates using an AD object directly for the Id parameter and using the RemoveRule switch.

        .EXAMPLE
            Import-Csv -Path ".\permissions.csv" | Set-AclConstructor6

            This example demonstrates pipeline input, assuming the CSV has appropriate column names matching parameter names.
            This allows for bulk permission operations defined in a CSV file.

        .INPUTS
            System.String
            System.DirectoryServices.ActiveDirectoryRights
            System.Security.AccessControl.AccessControlType
            System.Guid
            System.DirectoryServices.ActiveDirectorySecurityInheritance
            System.Boolean

            You can pipe objects with properties that match the parameter names.

        .OUTPUTS
            System.Void
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
                Write-Debug                                ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         4.0
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Private/Set-AclConstructor6.ps1

        .LINK
            https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adobject
            https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl
            https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl
            https://msdn.microsoft.com/en-us/library/system.directoryservices.activedirectoryrights
            https://msdn.microsoft.com/en-us/library/system.directoryservices.activedirectorysecurityinheritance
            https://msdn.microsoft.com/en-us/library/w72e8e69.aspx

        .COMPONENT
            Active Directory

        .ROLE
            Security

        .FUNCTIONALITY
            AD Permission Management, Access Control, Delegation of Control
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
            ValueFromRemainingArguments = $true,
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
            ValueFromRemainingArguments = $true,
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
            ValueFromRemainingArguments = $true,
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
        [ValidateSet([AccessControlType])]
        [String]
        $AccessControlType,

        # PARAM5 STRING representing the object GUID
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
            HelpMessage = 'Security inheritance of the new right (All, Children, Descendent, None, SelfAndChildren)',
            Position = 5)]
        [ValidateSet([ActiveDirectorySecurityInheritance])]
        [Alias('InheritanceType', 'ActiveDirectorySecurityInheritance')]
        [String]
        $AdSecurityInheritance,

        # PARAM7 Object GUID (or Extended Right)
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'GUID of the Inherited object or Extended Right',
            Position = 6)]
        [AllowNull()]
        $InheritedObjectType,

        # PARAM8 SWITCH if $false (default) will add the rule. If $true, it will remove the rule
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 7)]
        [Switch]
        $RemoveRule
    )

    Begin {
        # Set strict mode to identify potential issues
        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.HeaderDelegation) {

            $txt = ($Variables.HeaderDelegation -f
                (Get-Date).ToShortDateString(),
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

        # Convert InheritedObjectType to GUID if it's a string
        if ($null -ne $PSBoundParameters['InheritedObjectType']) {

            if ($PSBoundParameters['InheritedObjectType'] -is [System.String]) {

                try {

                    $InheritedObjectTypeGuid = [Guid]::Parse($PSBoundParameters['InheritedObjectType'])

                    Write-Debug -Message (
                        'Successfully parsed InheritedObjectType string to GUID: {0}' -f
                        $InheritedObjectTypeGuid
                    )

                } catch {

                    Write-Error -Message (
                        'Failed to parse InheritedObjectType as GUID: {0}' -f
                        $PSBoundParameters['InheritedObjectType']
                    )
                    throw

                } #end try-catch

            } elseif ($PSBoundParameters['InheritedObjectType'] -is [Guid]) {

                $InheritedObjectTypeGuid = $PSBoundParameters['InheritedObjectType']
                Write-Debug -Message ('Using provided InheritedObjectType GUID: {0}' -f $InheritedObjectTypeGuid)

            } #end if-elseif

        } #end if

    } #end Begin

    Process {
        try {
            #############################
            # Identify and resolve the trustee
            #############################

            Write-Debug -Message ('Beginning to resolve identity: {0}' -f $Id)

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
            $ActiveDirectoryRight = [DirectoryServices.ActiveDirectoryRights]$PSBoundParameters['AdRight']

            # 3. Access Control Type (Allow/Deny)
            $ACType = [System.Security.AccessControl.AccessControlType]$PSBoundParameters['AccessControlType']

            # 4. Object Type (GUID)
            # Parameter already properly typed as Guid

            # 5. Security Inheritance
            $SecurityInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]$PSBoundParameters['AdSecurityInheritance']

            # 6. Inherited Object Type (GUID)
            # Parameter already properly typed as Guid

            # Create Access Rule object
            $AccessRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                $IdentityRef,
                $ActiveDirectoryRight,
                $ACType,
                $ObjectTypeGuid,
                $SecurityInheritance,
                $InheritedObjectTypeGuid
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
                        $_.InheritanceType -eq $SecurityInheritance -and
                        $_.InheritedObjectType -eq $InheritedObjectTypeGuid
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
                'adding/removing access rule with 6 arguments (Private Function).'
            )
            Write-Verbose -Message $txt
        } #end if

    } #end END
} #end Function Set-AclConstructor6

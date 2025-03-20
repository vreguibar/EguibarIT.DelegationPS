# Constructor W/5 attributes https://msdn.microsoft.com/en-us/library/cawwkf0x.aspx

function Set-AclConstructor5 {
    <#
        .Synopsis
            Modifies ACLs on Active Directory objects.

        .DESCRIPTION
            This function adds or removes access rules to an Active Directory object
            using a constructor with 5 parameters to specify the access rule details.
            It supports batch processing and is optimized for large AD environments.

        .PARAMETER Id
            Specifies the SamAccountName of the delegated group or user.
            This is the identity for which the access rule will be modified.
            It can be a variable containing the AD group.

        .PARAMETER LDAPPath
            Specifies the LDAP path of the target Active Directory object.

        .PARAMETER AdRight
            Specifies the Active Directory rights. Valid options include CreateChild, DeleteChild, and others.

        .PARAMETER AccessControlType
            Specifies whether the access control is to Allow or Deny.

        .PARAMETER ObjectType
            Specifies the object type GUID. Use for specific property access or extended rights.

        .PARAMETER AdSecurityInheritance
            Security inheritance of the new right (All, Children, Descendents, None, SelfAndChildren)

        .PARAMETER RemoveRule
            If specified, the access rule will be removed. If omitted, the access rule will be added.

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

        .OUTPUTS
            [void]

        .NOTES
            Used Functions:
                 Name                                      ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Get-ADObject                               ║ ActiveDirectory
                Get-Acl                                    ║ Microsoft.PowerShell.Security
                Set-Acl                                    ║ Microsoft.PowerShell.Security
                Test-IsValidDN                             ║ EguibarIT.DelegationPS
                Get-AdObjectType                           ║ EguibarIT.DelegationPS
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Test-IsValidDN                             ║ EguibarIT.DelegationPS

        .NOTES
            Version:         3.0
            DateModified:    18/Mar/2025
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adobject
            https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl
            https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl
            https://msdn.microsoft.com/en-us/library/w72e8e69.aspx
            https://msdn.microsoft.com/en-us/library/system.directoryservices.activedirectoryrights
            https://msdn.microsoft.com/en-us/library/system.directoryservices.activedirectorysecurityinheritance

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Private/Set-AclConstructor5.ps1
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
        [ValidateSet([ActiveDirectorySecurityInheritance], ErrorMessage = "Value '{0}' is invalid. Try one of: {1}")]
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
        if ($null -ne $Variables -and $null -ne $Variables.HeaderDelegation) {
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
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'adding access rule with 5 arguments (Private Function).'
        )
        Write-Verbose -Message $txt
    } #end END
}

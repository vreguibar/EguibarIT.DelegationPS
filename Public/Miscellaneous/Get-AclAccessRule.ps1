Function Get-AclAccessRule {
    <#
        .SYNOPSIS
            Retrieves and displays Access Control Entries (ACEs) of an Active Directory object.

        .DESCRIPTION
            This function retrieves and displays the Access Control Entries (ACEs) of a specified Active Directory object.
            It can filter the results by identity reference. The function supports both pipeline input and batch processing
            for efficient handling of multiple objects. Use this function to analyze and audit permissions on AD objects.

            The Tool will return an arrayList with the following information:

            ACENumber             : 1
            Id                    : Everyone
            AdRight               : DeleteTree, Delete
            AccessControlType     : Deny
            ObjectType            : All [GuidNULL]
            AdSecurityInheritance : None
            InheritedObjectType   : All [GuidNULL]
            IsInherited           : False

            Explanation:
            * ACENumber: Sequential number of the ACE
            * Id: Identity Reference (trustee / SamAccountName)
            * LDAPpath: Distinguished Name of the object
            * AdRight: Active Directory rights granted
                ('AccessSystemSecurity', 'CreateChild', 'DeleteChild', 'Delete', 'DeleteTree', 'ExtendedRight',
                'GenericAll', 'GenericExecute', 'GenericRead', 'GenericWrite', 'ListChildren', 'ListObject',
                'ReadControl', 'ReadProperty', 'Self', 'Synchronize', 'WriteDacl', 'WriteOwner' or 'WriteProperty')
            * AccessControlType: Allow or Deny
            * ObjectType: GUID of the object type (translated to readable name)
            * AdSecurityInheritance: Inheritance type
                ('None', 'All', 'Descendents', 'SelfAndChildren', 'Children')
            * InheritedObjectType: GUID of the inherited object type (translated to readable name)
            * IsInherited: Whether the ACE is inherited (True or False)

        .FUNCTIONALITY
            Output from this function can be used by the Set-AclConstructor* functions to create new ACEs
             and apply them to objects. As a guidance, use:

                * Set-AclConstructor4 when we have available ID, AdRight, AccessControlType and ObjectType
                    Get-AclAccessRule4 output
                        ACENumber              : 1
                        DistinguishedName      : CN=Schema,CN=Configuration,DC=EguibarIT,DC=local
                        Id                     : EguibarIT\XXXX
                        ActiveDirectoryRights  : ExtendedRight
                        AccessControlType      : Allow
                        ObjectType             : Change Schema Master [Extended Rights]
                        X    InheritanceType        : None
                        X    InheritedObjectType    : GuidNULL
                        X    IsInherited            : False

                        $Splat = @{
                            LDAPPath          = 'CN=Schema,CN=Configuration,DC=EguibarIT,DC=local'
                            Id                = 'EguibarIT\XXXX'
                            AdRight           = 'ExtendedRight'
                            AccessControlType = 'Allow'
                            ObjectType        = 'Change Schema Master [Extended Rights]'
                        }
                        Set-AclConstructor4 @Splat

                * Set-AclConstructor5 when we have same as above, plus AdSecurityInheritance
                    Get-AclAccessRule5 output
                        ACENumber             : 1
                        DistinguishedName     : CN=Sites,CN=Configuration,DC=EguibarIT,DC=local
                        Id                    : EguibarIT\XXXX
                        AdRight               : ReadProperty, WriteProperty
                        AccessControlType     : Allow
                        ObjectType            : siteLink [classSchema]
                        AdSecurityInheritance : All
                        X    InheritedObjectType   : All [GuidNULL]
                        X    IsInherited           : False

                        $Splat = @{
                            LDAPPath              = 'CN=Sites,CN=Configuration,DC=EguibarIT,DC=local'
                            Id                    = 'EguibarIT\XXXX'
                            AdRight               = ReadProperty, WriteProperty
                            AccessControlType     = 'Allow'
                            ObjectType            = 'siteLink [classSchema]'
                            AdSecurityInheritance = All
                        }
                        Set-AclConstructor5 @Splat

                * Set-AclConstructor6 when we have same as above, plus InheritedObjectType
                Get-AclAccessRule6 output
                    ACE number          : 1
                    DistinguishedName   : CN=Sites,CN=Configuration,DC=EguibarIT,DC=local
                    Id                  : EguibarIT\XXXX
                    AdRight             : CreateChild, DeleteChild
                    AccessControlType   : Allow
                    ObjectType          : GuidNULL
                    InheritanceType     : Descendents
                    InheritedObjectType : site [ClassSchema]
                    X    IsInherited         : False

                        $Splat = @{
                            LDAPPath              = 'CN=Sites,CN=Configuration,DC=EguibarIT,DC=local'
                            Id                    = 'EguibarIT\XXXX'
                            AdRight               = CreateChild, DeleteChild
                            AccessControlType     = 'Allow'
                            ObjectType            = GuidNULL
                            AdSecurityInheritance = All
                            InheritedObjectType   = site [ClassSchema]
                        }
                        Set-AclConstructor6 @Splat


        .PARAMETER LDAPPath
            Distinguished Name of the Active Directory object to retrieve ACEs from.
            Multiple objects can be passed via pipeline or as an array.

        .PARAMETER SearchBy
            Optional parameter to filter ACEs by Identity Reference (Trustee).
            If provided, only ACEs matching this identity will be returned.

        .EXAMPLE
            Get-AclAccessRule -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"

            Retrieves all ACEs for the specified OU.

        .EXAMPLE
            Get-AclAccessRule "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" "Pre-Windows 2000 Compatible Access"

            Retrieves ACEs for the specified OU, filtering only those assigned to "Pre-Windows 2000 Compatible Access".

        .EXAMPLE
            $Splat = @{
                LDAPPath = "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
                SearchBy = "Pre-Windows 2000 Compatible Access"
            }
            Get-AclAccessRule @Splat

            Retrieves filtered ACEs from the specified OU

        .EXAMPLE
            Get-ADOrganizationalUnit -Filter "Name -like 'IT*'" | Get-AclAccessRule

            Retrieves ACEs for all OUs with names starting with "IT", demonstrating pipeline integration with AD cmdlets.

        .OUTPUTS
            [System.Collections.ArrayList] containing PSCustomObjects with ACE properties
            Each object contains:
            - ACENumber: Sequential number of the ACE
            - Id: Identity Reference (trustee)
            - LDAPpath: Distinguished Name of the object
            - AdRight: Active Directory rights granted
            - AccessControlType: Allow or Deny
            - ObjectType: GUID of the object type (translated to readable name)
            - AdSecurityInheritance: Inheritance type
            - InheritedObjectType: GUID of the inherited object type (translated to readable name)
            - IsInherited: Whether the ACE is inherited

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Get-Acl                                ║ Microsoft.PowerShell.Security
                Set-Location                           ║ Microsoft.PowerShell.Management
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Progress                         ║ Microsoft.PowerShell.Utility
                Write-Warning                          ║ Microsoft.PowerShell.Utility
                Write-Error                            ║ Microsoft.PowerShell.Utility
                Test-IsValidDN                         ║ EguibarIT.DelegationPS
                Convert-GUIDToName                     ║ EguibarIT.DelegationPS
                Get-FunctionDisplay                    ║ EguibarIT.DelegationPS
                Import-MyModule                        ║ EguibarIT.DelegationPS

        .NOTES
            Version:         2.0
            DateModified:    21/Mar/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://devblogs.microsoft.com/powershell-community/understanding-get-acl-and-ad-drive-output/
            https://github.com/PowerShell/Community-Blog/issues/70

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Public/Miscellaneous/Get-AclAccessRule.ps1
    #>

    [CmdletBinding(SupportsShouldProcess = $false,
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.Collections.ArrayList])]

    param
    (
        # PARAM1 LDAP path to the object to get the ACL
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the object',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            { Test-IsValidDN -ObjectDN $_ },
            ErrorMessage = 'DistinguishedName provided is not valid! Please Check.'
        )]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        # PARAM1 Search by Identity Reference
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'The identity to filter ACE',
            Position = 1)]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        [String]
        $SearchBy
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
        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false

        ##############################
        # Variables Definition
        [System.Collections.ArrayList]$result = [System.Collections.ArrayList]::New()
        [System.Text.StringBuilder]$sb = [System.Text.StringBuilder]::new()

        # Define ANSI escape codes for colors
        $reset = "`e[0m"    # Reset color
        $red = "`e[31m"   # Red
        $green = "`e[32m"   # Green
        $yellow = "`e[33m"   # Yellow
        $brown = "`e[33;2m" # Brown (Dark Yellow)
        $blue = "`e[34m"   # Blue
        $purple = "`e[35m"   # Purple
        $gray = "`e[90m"   # Gray
        $orange = "`e[91m"   # Orange (Bright Red)
        $green = "`e[92m"   # Bright Green
        $cyan = "`e[96m"   # Light Blue (Cyan)
        $white = "`e[97m"   # White

        # Set location to AD: drive
        try {

            Set-Location -Path 'AD:\' -ErrorAction Stop

        } catch {

            Write-Error -Message ('Failed to set location to AD:\ drive: {0}' -f $_.Exception.Message)
            return

        } #end try-catch

    } #end Begin

    Process {

        # Clear StringBuilder for new processing
        [void]$sb.Clear()
        [void]$sb.AppendLine()

        Write-Verbose -Message ('Processing LDAP path: {0}' -f $LDAPPath)


        Try {
            # Get the ACL for the current path
            $Acl = Get-Acl -Path $PSBoundParameters['LDAPpath'] -ErrorAction Stop

            # Check if ACL was retrieved successfully
            if ($null -eq $Acl) {

                Write-Error -Message ('Failed to retrieve ACL for {0}' -f $PSBoundParameters['LDAPpath'])
                return

            } #end If

            If ($PSBoundParameters['searchBy']) {

                $AclAccess = @($Acl |
                        Select-Object -ExpandProperty Access |
                            Where-Object -FilterScript {
                                $_.IdentityReference -match $PSBoundParameters['searchBy']
                            })

                [void]$sb.AppendLine('       ACE (Access Control Entry)')
                [void]$sb.AppendLine('            Filtered By: {0}' -f $PSBoundParameters['SearchBy'])

            } else {

                $AclAccess = @($Acl | Select-Object -ExpandProperty Access)

                [void]$sb.AppendLine('       All ACE (Access Control Entry)')

            } #end If-Else

            # Check if any ACEs were found
            if ($null -eq $AclAccess -or $AclAccess.Count -eq 0) {

                Write-Warning -Message "No matching ACEs found for $($PSBoundParameters['LDAPpath'])"
                return

            } #end If


            [void]$sb.AppendLine('       LDAPpath : {0}' -f $LDAPpath)
            [void]$sb.AppendLine('       Total ACE found : {0}' -f $AclAccess.count)
            [void]$sb.AppendLine('------------------------------------------------------------')

            # Process each ACE
            $AceCount = $AclAccess.Count
            for ($i = 0; $i -lt $AceCount; $i++) {
                # Update progress bar
                Write-Progress -Activity 'Processing Access Control Entries' -Status ('Processing entry {0} of {1}' -f ($i + 1), $AceCount) -PercentComplete (($i + 1) / $AceCount * 100)

                # Get the current ACE
                $entry = $AclAccess[$i]

                $ACLResult = [PSCustomObject]@{
                    ACENumber             = $i + 1
                    Id                    = $entry.IdentityReference.Value
                    LDAPpath              = $LDAPpath
                    AdRight               = $entry.ActiveDirectoryRights
                    AccessControlType     = $entry.AccessControlType
                    ObjectType            = (Convert-GUIDToName -guid $entry.ObjectType -Verbose:$false)
                    AdSecurityInheritance = $entry.InheritanceType
                    InheritedObjectType   = (Convert-GUIDToName -guid $entry.InheritedObjectType -Verbose:$false)
                    IsInherited           = $entry.IsInherited
                }
                [void]$result.Add($ACLResult)

            } #end Foreach

            # Complete the progress bar
            Write-Progress -Activity 'Processing Access Control Entries' -Completed

        } catch [System.Security.Principal.IdentityNotMappedException] {

            Write-Warning -Message ('
                Identity mapping error for {0}: {1}' -f $PSBoundParameters['LDAPpath'], $_.Exception.Message
            )

        } catch [System.DirectoryServices.DirectoryServicesCOMException] {

            Write-Warning -Message ('
                Directory Services error for {0}: {1}' -f $PSBoundParameters['LDAPpath'], $_.Exception.Message
            )

        } catch {

            Write-Error -Message ('
                Error retrieving ACL for {0}: {1}' -f $PSBoundParameters['LDAPpath'], $_.Exception.Message
            )

        } #end try-catch
    } #end Process

    End {
        # Display footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'getting ACL.'
            )
            Write-Verbose -Message $txt
        } #end if

        # Return to home drive
        try {

            Set-Location -Path $env:HOMEDRIVE\ -ErrorAction Stop

        } catch {

            Write-Warning -Message ('Failed to return to home drive: {0}' -f $_.Exception.Message)

        } #end try-catch

        # If results are available and not being piped elsewhere, format them for display
        if ($result.Count -gt 0 -and $MyInvocation.ExpectingInput -eq $false) {

            $sb.ToString()

            $Splat = @{
                InputObject = $result
                Property    = 'ACENumber',
                @{Name = 'Id'; Expression = { "$blue$($_.Id)$reset" } },
                @{Name = 'AdRight'; Expression = { "$blue$($_.AdRight)$reset" } },
                @{Name = 'AccessControlType'; Expression = { "$blue$($_.AccessControlType)$reset" } },
                @{Name = 'ObjectType'; Expression = { "$blue$($_.ObjectType)$reset" } },
                @{Name = 'AdSecurityInheritance'; Expression = { "$yellow$($_.AdSecurityInheritance)$reset" } },
                @{Name = 'InheritedObjectType'; Expression = { "$purple$($_.InheritedObjectType)$reset" } },
                @{Name = 'IsInherited'; Expression = { "$cyan$($_.IsInherited)$reset" } }
            }
            Format-List @Splat

        } else {

            # Return the result for pipeline operations
            Return $result

        } #end If-Else
    } #end End
} #end Function Get-AclAccessRule

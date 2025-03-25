Function Remove-UnknownSID {
    <#
        .SYNOPSIS
            Removes unresolvable SIDs from Active Directory object permissions.

        .DESCRIPTION
            This function identifies and optionally removes unresolvable Security Identifiers (SIDs) from
            the Access Control Entries (ACEs) of specified Active Directory objects. An unresolvable SID
            typically indicates a deleted security principal (user, group, or computer).

            The function:
            - Identifies SIDs that cannot be resolved to friendly names
            - Excludes well-known SIDs from removal
            - Supports both audit and removal modes
            - Processes single objects or pipeline input
            - Implements proper transaction handling for ACL modifications

        .PARAMETER LDAPpath
            The Distinguished Name of the Active Directory object to check for unresolvable SIDs.
            This parameter accepts pipeline input and must be a valid DN format.

        .PARAMETER RemoveSID
            Switch parameter that determines whether to remove the unresolvable SIDs.
            If not specified, the function will only report the unresolvable SIDs.

        .EXAMPLE
            Remove-UnknownSID -LDAPpath "OU=Users,OU=Good,OU=Sites,DC=EguibarIT,DC=local"

            Lists all unresolvable SIDs found in the specified OU without removing them.

        .EXAMPLE
            Remove-UnknownSID -LDAPpath "OU=Users,OU=Good,OU=Sites,DC=EguibarIT,DC=local" -RemoveSID

            Removes all unresolvable SIDs from the specified OU's ACL.

        .EXAMPLE
            Get-ADOrganizationalUnit -Filter * | Remove-UnknownSID -RemoveSID

            Removes unresolvable SIDs from all OUs in the domain.

        .OUTPUTS
            [void]

        .NOTES
            Used Functions:
                Name                                 ║ Module
                ═════════════════════════════════════╬══════════════════════════════
                Test-IsValidDN                       ║ EguibarIT.DelegationPS
                Get-AdWellKnownSID                   ║ EguibarIT.DelegationPS
                Convert-SidToName                    ║ EguibarIT.DelegationPS
                Write-Verbose                        ║ Microsoft.PowerShell.Utility
                Write-Warning                        ║ Microsoft.PowerShell.Utility
                Write-Error                          ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.1
            DateModified:    24/Mar/2025
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Public/Miscellaneous/Remove-UnknownSID.ps1

        .LINK
            https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers

        .COMPONENT
            ActiveDirectory

        .ROLE
            Security Administration
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([void])]

    Param (
        # PARAM1 STRING for the Object Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the object (or container) where the Unknown SID is located.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            { Test-IsValidDN -ObjectDN $_ },
            ErrorMessage = 'DistinguishedName provided is not valid! Please Check.'
        )]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Switch indicator to remove the unknown SID.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [switch]
        $RemoveSID
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
        $myObject = $null
        $AllRules = $null
        $rule = $null

    } # end Begin

    Process {

        # Get the LDAP object to get the access rules from
        $myObject = [System.DirectoryServices.DirectoryEntry]::new('LDAP://{0}' -f $PSBoundParameters['LDAPPath'])

        if (-not $myObject) {
            throw ('Failed to access object: {0}' -f $LDAPpath)
        }

        # Get the access rules
        $AllRules = $myObject.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

        Write-Verbose -Message ('Found {0} rules in this object. Iterating through them.' -f $AllRules.count)

        # Iterate through all Access Control rules
        foreach ($rule in $AllRules) {
            #$oar = $rule -as [System.Security.AccessControl.ActiveDirectoryAccessRule]

            # Check if WellKnownSid. Skipping WellKnownSIDs. Continue if not.
            if (-not (Get-AdWellKnownSID -Sid ($rule.IdentityReference.Value))) {


                # Translate SID. True if exists. False if it does not exist.
                if (-not (Convert-SidToName -Sid $rule.IdentityReference.ToString())) {

                    Write-Verbose -Message ('Unresolved SID found! {0}' -f $($rule.IdentityReference.ToString()))

                    if ($PSBoundParameters['RemoveSID']) {

                        Write-Verbose -Message 'Preparing to remove un-resolved SID'

                        try {
                            # Remove unknown SID from rule
                            If ($Force -or
                                $PSCmdlet.ShouldProcess($PSBoundParameters['LDAPpath'], 'Remove unknown SID?')) {

                                $myObject.ObjectSecurity.RemoveAccessRule($rule)

                            } #end If

                            Write-Verbose -Message ('Successfully removed SID: {0}' -f $rule.IdentityReference)

                        } catch {

                            Write-Error -Message ('Failed to remove SID {0}: {1}' -f $rule.IdentityReference, $_.Exception.Message)
                            continue

                        } #end Try-Catch

                    } else {

                        Write-Warning -Message ('Unresolvable SID found: {0}' -f $rule.IdentityReference.ToString())

                    } #end If-Else
                } #end If
            } #end If
        } #end ForEach

        # Commit changes if any SIDs were removed
        if ($RemoveSID -and $unknownSidsFound -gt 0) {
            try {
                # Re-apply the modified DACL to the OU
                # Now push these AccessRules to AD
                $myObject.CommitChanges()

                Write-Verbose -Message ('Successfully committed changes to {0}' -f $LDAPpath)

            } catch {
                throw [System.ApplicationException]::new("An error occurred while committing changes to the access rule: '$($_.Exception)'. Message is $($_.Exception.Message)")
            } #end Try-Catch
        } #end if

    } # end Process

    End {

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'detecting and removing unresolved SIDs.'
            )
            Write-Verbose -Message $txt
        } #end If

        if ($null -ne $myObject) {
            $myObject.Dispose()
        }

    } #end END
} #end function Remove-UnknownSID

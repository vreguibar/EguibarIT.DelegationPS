Function Remove-UnknownSID {
    <#
        .Synopsis
            Remove Un-Resolvable SID from a given object
        .DESCRIPTION
            Remove Un-Resolvable SID from a given object. If a SID is displayed within the ACE, is
            because a name could not be resolved. Most likely the object was deleted, and its friendly
            name could not be retrived. This function will identify this unresolved SID and remove it from the ACE
        .EXAMPLE
            Remove-UnknownSID -LDAPpath "OU=Users,OU=Good,OU=Sites,DC=EguibarIT,DC=local"
        .EXAMPLE
            Remove-UnknownSID -LDAPpath "OU=Users,OU=Good,OU=Sites,DC=EguibarIT,DC=local" -RemoveSID
        .PARAMETER LDAPpath
            [String] Distinguished Name of the object (or container) where the Unknown SID is located
        .PARAMETER RemoveSID
            Switch indicator to remove the unknown SID
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
        .NOTES
            Version:         1.0
            DateModified:    21/Sep/2022
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    Param (
        # PARAM1 STRING for the Object Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the object (or container) where the Unknown SID is located.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Switch indicator to remove the unknown SID.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [switch]
        $RemoveSID
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

    } # end Begin

    Process {

        # Get the LDAP object to get the access rules from
        $myObject = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PSBoundParameters['LDAPPath']")

        # Get the access rules
        $rules = $myObject.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

        # Iterate through all Access Control rules
        foreach ($rule in $rules) {
            #$oar = $rule -as [System.Security.AccessControl.ActiveDirectoryAccessRule]
            $oar = $rule

            # Check if WellKnownSid. Skipping WellKnownSIDs. Continue if not.
            if (-not (Get-AdWellKnownSID -Sid ($oar.IdentityReference.Value))) {
                # Translate SID. True if exists. False if it does not exist.
                if (-not (EguibarIT.Delegation.SIDs::SidExists($oar.IdentityReference.ToString()))) {
                    Write-Verbose "Unresolved SID found! $($oar.IdentityReference.ToString())"

                    if ($_removesid) {
                        try {
                            # Remove unknown SID from rule
                            $myObject.ObjectSecurity.RemoveAccessRule($oar)
                        } catch {
                            throw [System.ApplicationException]::new("An error occurred while removing access rule: '$($_.Exception)'. Message is $($_.Exception.Message)")
                        } finally {
                            Write-Verbose "SID removed! $($oar.IdentityReference.ToString())"
                        }
                    } else {
                        Write-Warning "---> SID does not exist! $($oar.IdentityReference.ToString())"
                    }
                }
            }
        }

        try {
            # Re-apply the modified DACL to the OU
            # Now push these AccessRules to AD
            $myObject.CommitChanges()
        } catch {
            throw [System.ApplicationException]::new("An error occurred while committing changes to the access rule: '$($_.Exception)'. Message is $($_.Exception.Message)")
        }

    } # end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating central OU."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}

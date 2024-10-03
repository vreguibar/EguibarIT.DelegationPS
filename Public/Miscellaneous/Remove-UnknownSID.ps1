Function Remove-UnknownSID {
    <#
        .Synopsis
            Remove Un-Resolvable SID from a given object
        .DESCRIPTION
            Remove Un-Resolvable SID from a given object. If a SID is displayed within the ACE, is
            because a name could not be resolved. Most likely the object was deleted, and its friendly
            name could not be retrieved. This function will identify this unresolved SID and remove it from the ACE
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
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    Param (
        # PARAM1 STRING for the Object Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the object (or container) where the Unknown SID is located.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ }, ErrorMessage = 'DistinguishedName provided is not valid! Please Check.')]
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

        $txt = ($Variables.HeaderDelegation -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

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
        $myObject = New-Object System.DirectoryServices.DirectoryEntry('LDAP://{0}' -f $PSBoundParameters['LDAPPath'])

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
                            If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['LDAPpath'], 'Remove unknown SID?')) {
                                $myObject.ObjectSecurity.RemoveAccessRule($rule)
                            } #end If

                            Write-Verbose -Message 'Un-resolved SID removed'

                        } catch {
                            throw [System.ApplicationException]::new("An error occurred while removing access rule: '$($_.Exception)'. Message is $($_.Exception.Message)")

                        } finally {
                            Write-Verbose -Message ('SID removed! {0}' -f $($rule.IdentityReference.ToString()))
                        } #end Try-Catch

                    } else {

                        $Constants.NL
                        Write-Warning "---> SID does not exist! $($rule.IdentityReference.ToString())"
                        $Constants.NL

                    } #end If-Else
                } #end If
            } #end If
        } #end ForEach

        try {
            # Re-apply the modified DACL to the OU
            # Now push these AccessRules to AD
            $myObject.CommitChanges()

            Write-Verbose -Message 'Committing changes.'
        } catch {
            throw [System.ApplicationException]::new("An error occurred while committing changes to the access rule: '$($_.Exception)'. Message is $($_.Exception.Message)")
        } #end Try-Catch

    } # end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'detecting and removing unresolved SIDs.'
        )
        Write-Verbose -Message $txt
    } #end END
}

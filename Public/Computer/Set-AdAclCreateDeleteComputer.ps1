function Set-AdAclCreateDeleteComputer {
    <#
        .SYNOPSIS
            Delegates permission for a group to create/delete Computer objects in an OU.

        .DESCRIPTION
            Configures the container (OU) to delegate the permissions to a group so it can create/delete computer objects.
            This function assigns the necessary permissions for computer account creation and management.

        .PARAMETER Group
            Identity of the group getting the delegation, usually a DomainLocal group.

        .PARAMETER LDAPpath
            Distinguished Name of the OU where the permissions will be set.

        .PARAMETER RemoveRule
            If present, the access rules will be removed instead of added.

        .EXAMPLE
            Set-AdAclCreateDeleteComputer -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Computers,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"

            Delegates Create/Delete computer permissions to the group "SG_SiteAdmins_XXXX" on the specified OU.

        .EXAMPLE
            Set-AdAclCreateDeleteComputer -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Computers,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule

            Removes the Create/Delete computer permissions from the group "SG_SiteAdmins_XXXX" on the specified OU.

        .INPUTS
            [String] Group
            [String] LDAPpath
            [Switch] RemoveRule

        .OUTPUTS
            None. This function does not generate any output.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Set-AclConstructor5                        ║ EguibarIT.DelegationPS
                Get-AttributeSchemaHashTable               ║ EguibarIT.DelegationPS
                Get-AdObjectType                           ║ EguibarIT.DelegationPS
                Test-IsValidDN                             ║ EguibarIT.DelegationPS
                Get-FunctionDisplay                        ║ EguibarIT.DelegationPS

        .NOTES
            Version:         1.3
            DateModified:    11/May/2023
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar Information Technology S.L.
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS

        .COMPONENT
            Active Directory

        .ROLE
            Security, ActiveDirectory, Delegation

        .FUNCTIONALITY
            Delegation, Computer Management
    #>
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([void])]

    Param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        $Group,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Distinguished Name of the OU where the permissions will be set.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            { Test-IsValidDN -ObjectDN $_ },
            ErrorMessage = 'Distinguished Name provided is not valid! Please check the format.'
        )]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
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
        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        try {

            Write-Verbose -Message 'Checking variable $Variables.GuidMap. In case it is empty, a function is called to fill it.'
            Get-AttributeSchemaHashTable

            # Verify Group exists and return it as Microsoft.ActiveDirectory.Management.AdGroup
            $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

            Write-Verbose -Message ('Group {0} found and ready for delegation' -f $PSBoundParameters['Group'])

        } catch {

            Write-Error -Message ('Error initializing variables or validating group: {0}' -f $_.Exception.Message)
            return

        }
    } #end Begin

    Process {
        <#
            ACE number: 1
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights : GenericAll
                  AccessControlType : Allow
                         ObjectType : computer [ClassSchema]
                    InheritanceType : Descendents
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        # Set the ACE for the group to have GenericAll permissions on descendant computer objects in the specified OU.
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['computer']
            AdSecurityInheritance = 'Descendents'
        }

        # Check if RemoveRule switch is present
        If ($PSBoundParameters['RemoveRule']) {

            if ($PSCmdlet.ShouldProcess($PSBoundParameters['LDAPpath'],
                ('Remove GenericAll permissions for {0} on descendant computer objects' -f $PSBoundParameters['Group']))) {

                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)

                Set-AclConstructor5 @Splat
                Write-Verbose -Message (
                    'Removed GenericAll permission for {0}
                        on descendant computer objects in {1}' -f
                    $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath']
                )
            } #end If

        } else {

            if ($PSCmdlet.ShouldProcess($PSBoundParameters['LDAPpath'],
                ('Grant GenericAll permissions for {0}
                on descendant computer objects' -f $PSBoundParameters['Group']))) {

                Set-AclConstructor5 @Splat
                Write-Verbose -Message (
                    'Granted GenericAll permission for {0} on descendant computer objects in {1}' -f
                    $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath']
                )
            } #end If

        } #end If-Else


        <#
            ACE number: 2
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : computer [ClassSchema]
                    InheritanceType : All
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'CreateChild', 'DeleteChild'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['computer']
            AdSecurityInheritance = 'All'
        }

        # Check if RemoveRule switch is present
        If ($PSBoundParameters['RemoveRule']) {

            if ($PSCmdlet.ShouldProcess($PSBoundParameters['LDAPpath'],
                ('Remove CreateChild/DeleteChild permissions for {0} on computer objects' -f $PSBoundParameters['Group']))) {

                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)

                Set-AclConstructor5 @Splat
                Write-Verbose -Message (
                    'Removed CreateChild/DeleteChild permissions for {0} in {1}' -f
                    $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath']
                )
            } #end If

        } else {

            if ($PSCmdlet.ShouldProcess($PSBoundParameters['LDAPpath'],
                ('Grant CreateChild/DeleteChild permissions for {0} on computer objects' -f $PSBoundParameters['Group']))) {

                Set-AclConstructor5 @Splat
                Write-Verbose -Message ('Granted CreateChild/DeleteChild permissions for {0} in {1}' -f
                    $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath'])
            } #end If

        } #end If-Else

    } #end Process

    End {
        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $ActionMessage = $(if ($PSBoundParameters['RemoveRule']) {
                    'removing'
                } else {
                    'delegating'
                })
            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                ('{0} Create/Delete computer permissions.' -f $ActionMessage)
            )
            Write-Verbose -Message $txt
        } #end if
    } #end End
} #end function Set-AdAclCreateDeleteComputer

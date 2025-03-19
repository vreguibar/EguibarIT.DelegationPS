# LAPS grant right to computer to SELF update PWD attributes
function Set-AdmPwdComputerSelfPermission {
    <#
        .Synopsis
            The function will delegate the right were the computer can self update password attributes
        .DESCRIPTION
            LAPS implementation. The function will delegate the right were the computer can self update admin password attributes
        .EXAMPLE
            Set-AdmPwdComputerSelfPermission -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .EXAMPLE
            Set-AdmPwdComputerSelfPermission -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .PARAMETER LDAPpath
            [STRING] Distinguished Name of the OU where the computer can self update password attributes
        .PARAMETER RemoveRule
            [SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor6                    | EguibarIT.DelegationPS
                Get-AttributeSchemaHashTable           | EguibarIT.DelegationPS
        .NOTES
            Version:         1.0
            DateModified:    19/Oct/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    Param     (
        # PARAM1 Distinguished Name of the OU where the computer can self update password attributes
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where the computer can self update password attributes.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ }, ErrorMessage = 'DistinguishedName provided is not valid! Please Check.')]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        # PARAM3 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
    )

    Begin {

        Set-StrictMode -Version Latest

        $txt = ($Variables.HeaderDelegation -f
            (Get-Date).ToString('dd/MMM/yyyy'),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        Write-Verbose -Message 'Checking variable $Variables.GuidMap. In case is empty a function is called to fill it up.'
        Get-AttributeSchemaHashTable
    } #end Begin

    Process {
        <#
            ACE number: 1
            --------------------------------------------------------
                  IdentityReference : SELF
             ActiveDirectoryRights : ReadProperty, WriteProperty
                  AccessControlType : Allow
                         ObjectType : ms-Mcs-AdmPwdExpirationTime [AttributeSchema]
                    InheritanceType : Descendents
                InheritedObjectType : computer [ClassSchema]
                        IsInherited = False
        #>
        $Splat = @{
            Id                    = 'SELF'
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['ms-Mcs-AdmPwdExpirationTime']
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['computer']

        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for ms-Mcs-AdmPwdExpirationTime?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions for ms-Mcs-AdmPwdExpirationTime?')) {
            Set-AclConstructor6 @Splat
        } #end If

        <#
            ACE number: 2
            --------------------------------------------------------
                  IdentityReference : SELF
             ActiveDirectoryRights : WriteProperty
                  AccessControlType : Allow
                         ObjectType : ms-Mcs-AdmPwd [AttributeSchema]
                    InheritanceType : Descendents
                InheritedObjectType : computer [ClassSchema]
                        IsInherited = False
        #>
        $Splat = @{
            Id                    = 'SELF'
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['ms-Mcs-AdmPwd']
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['computer']
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for ms-Mcs-AdmPwd?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions for ms-Mcs-AdmPwd?')) {
            Set-AclConstructor6 @Splat
        } #end If
    }

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0} on {1}' -f $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0} on {1}' -f $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath'])
        } #end If-Else

        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'delegating change Computer Self Service Permission.'
        )
        Write-Verbose -Message $txt
    } #end END
}

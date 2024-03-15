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
                Set-AclConstructor6                    | EguibarIT.Delegation
                Get-AttributeSchemaHashTable                | EguibarIT.Delegation
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
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where the computer can self update password attributes.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPpath,

        # PARAM3 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New()

        If ( ($null -eq $Variables.GuidMap) -and
                 ($Variables.GuidMap -ne 0) -and
                 ($Variables.GuidMap -ne '') -and
                 (   ($Variables.GuidMap -isnot [array]) -or
                     ($Variables.GuidMap.Length -ne 0)) -and
                 ($Variables.GuidMap -ne $false)
        ) {
            # $Variables.GuidMap is empty. Call function to fill it up
            Write-Verbose -Message 'Variable $Variables.GuidMap is empty. Calling function to fill it up.'
            Get-AttributeSchemaHashTable
        } #end If
    } #end Begin

    Process {
        <#
            ACE number: 1
            --------------------------------------------------------
                  IdentityReference : SELF
             ActiveDirectoryRightst : ReadProperty, WriteProperty
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

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for ms-Mcs-AdmPwdExpirationTime?')) {
            Set-AclConstructor6 @Splat
        } #end If

        <#
            ACE number: 2
            --------------------------------------------------------
                  IdentityReference : SELF
             ActiveDirectoryRightst : WriteProperty
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

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for ms-Mcs-AdmPwd?')) {
            Set-AclConstructor6 @Splat
        } #end If
    }

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0} on {1}' -f $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0} on {1}' -f $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath'])
        } #end If-Else

        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}

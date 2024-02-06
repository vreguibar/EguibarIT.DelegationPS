Function Set-AdAclMngPrivilegedAccounts {
       <#
        .Synopsis
            The function will delegate the premission for a group to Managed Privileged Accounts
        .DESCRIPTION
            The function will delegate the premission for a group to Managed Privileged Accounts
        .EXAMPLE
            Set-AdAclMngPrivilegedAccounts -Group "SL_PUM" -RemoveRule
        .EXAMPLE
            Set-AdAclMngPrivilegedAccounts -Group "SL_PUM" -RemoveRule
        .PARAMETER Group
            [STRING] Identity of the group getting the delegation.
        .PARAMETER RemoveRule
            [SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor5                    | EguibarIT.Delegation
                New-GuidObjectHashTable                | EguibarIT.Delegation
                New-ExtenderRightHashTable             | EguibarIT.Delegation
        .NOTES
            Version:         1.2
            DateModified:    07/Dec/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]

    Param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference','Identity','Trustee','GroupID')]
        [String]
        $Group,

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
        $parameters = $null

        If ( ($null -eq $Variables.GuidMap) -and
                 ($Variables.GuidMap -ne 0)     -and
                 ($Variables.GuidMap -ne '')    -and
                 (   ($Variables.GuidMap -isnot [array]) -or
                     ($Variables.GuidMap.Length -ne 0)) -and
                 ($Variables.GuidMap -ne $false)
            ) {
            # $Variables.GuidMap is empty. Call function to fill it up
            Write-Verbose -Message 'Variable $Variables.GuidMap is empty. Calling function to fill it up.'
            New-GuidObjectHashTable
        } #end If

        If ( ($null -eq $Variables.ExtendedRightsMap) -and
                 ($Variables.ExtendedRightsMap -ne 0)     -and
                 ($Variables.ExtendedRightsMap -ne '')    -and
                 (   ($Variables.ExtendedRightsMap -isnot [array]) -or
                     ($Variables.ExtendedRightsMap.Length -ne 0)) -and
                 ($Variables.ExtendedRightsMap -ne $false)
            ) {
            # $Variables.ExtendedRightsMap is empty. Call function to fill it up
            Write-Verbose -Message 'Variable $Variables.ExtendedRightsMap is empty. Calling function to fill it up.'
            New-ExtenderRightHashTable
        } #end If
    } #end Begin

    Process {
        <#
            dsacls "CN=AdminSDHolder,CN=System,DC=EguibarIT,DC=local" /G "EguibarIT\SL_PUM":RPWP;member

            dsacls "CN=AdminSDHolder,CN=System,DC=EguibarIT,DC=local" /G "EguibarIT\SL_PUM":CA;"Reset Password"
            dsacls "CN=AdminSDHolder,CN=System,DC=EguibarIT,DC=local" /G "EguibarIT\SL_PUM":RPWP;lockoutTime
            dsacls "CN=AdminSDHolder,CN=System,DC=EguibarIT,DC=local" /G "EguibarIT\SL_PUM":RPWP;pwdLastSet

            dsacls "CN=AdminSDHolder,CN=System,DC=EguibarIT,DC=local" /G "EguibarIT\SL_PUM":RPWP;userAccountControl
            dsacls "CN=AdminSDHolder,CN=System,DC=EguibarIT,DC=local" /G "EguibarIT\SL_PUM":CA;"Change Password"
            dsacls "CN=AdminSDHolder,CN=System,DC=EguibarIT,DC=local" /G "EguibarIT\SL_PUM":RPWP;lockoutTime
        #>
        <#
            ACE number: 1
            --------------------------------------------------------
                 IdentityReference : XXX
             ActiveDirectoryRightst : ReadProperty, WriteProperty
                  AccessControlType : Allow
                         ObjectType : member [AttributeSchema]
                    InheritanceType : None
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=AdminSDHolder,CN=System,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['member']
            AdSecurityInheritance = 'None'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters

        <#
            ACE number: 2
            --------------------------------------------------------
                 IdentityReference : XXX
             ActiveDirectoryRightst : ReadProperty, WriteProperty
                  AccessControlType : Allow
                         ObjectType : lockoutTime [AttributeSchema]
                    InheritanceType : None
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=AdminSDHolder,CN=System,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['lockoutTime']
            AdSecurityInheritance = 'None'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters

        <#
            ACE number: 3
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : ReadProperty, WriteProperty
                  AccessControlType : Allow
                         ObjectType : userAccountControl [AttributeSchema]
                    InheritanceType : None
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=AdminSDHolder,CN=System,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['userAccountControl']
            AdSecurityInheritance = 'None'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters
        <#
            ACE number: 4
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : ReadProperty, WriteProperty
                  AccessControlType : Allow
                         ObjectType : pwdLastSet [AttributeSchema]
                    InheritanceType : None
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=AdminSDHolder,CN=System,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['pwdLastSet']
            AdSecurityInheritance = 'None'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters

        <#
            ACE number: 5
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : ExtendedRight
                  AccessControlType : Allow
                         ObjectType : Reset Password [ExtendedRight]
                    InheritanceType : None
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=AdminSDHolder,CN=System,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.ExtendedRightsMap['Reset Password']
            AdSecurityInheritance = 'None'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters

        <#
            ACE number: 6
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : ExtendedRight
                  AccessControlType : Allow
                         ObjectType : Change Password [ExtendedRight]
                    InheritanceType : None
                InheritedObjectType : GuidNULL
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = 'CN=AdminSDHolder,CN=System,{0}' -f $Variables.defaultNamingContext
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.ExtendedRightsMap['Change Password']
            AdSecurityInheritance = 'None'
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor5 @parameters
    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}

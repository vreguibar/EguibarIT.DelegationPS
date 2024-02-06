﻿Function Set-AdAclCreateDeleteGMSA {
    Function Set-AdAclCreateDeleteMSA {
        <#
            .Synopsis
                The function will delegate the premission for a group to Create/Delete Group Managed Service Accounts
            .DESCRIPTION
                The function will delegate the premission for a group to Create/Delete Group Managed Service Accounts
            .EXAMPLE
                Set-AdAclCreateDeleteGMSA -Group "SL_CreateUserRight" -LDAPpath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
            .EXAMPLE
                Set-AdAclCreateDeleteGMSA -Group "SL_CreateUserRight" -LDAPpath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
            .PARAMETER Group
                [STRING] Identity of the group getting the delegation, usually a DomainLocal group.
            .PARAMETER LDAPpath
                [STRING] Distinguished Name of the object (or container) where the permissions are going to be configured.
            .PARAMETER RemoveRule
                [SWITCH] If present, the access rule will be removed
            .NOTES
                Used Functions:
                    Name                                   | Module
                    ---------------------------------------|--------------------------
                    Set-AclConstructor5                    | EguibarIT.Delegation
                    Set-AclConstructor6                    | EguibarIT.Delegation
                    New-GuidObjectHashTable                | EguibarIT.Delegation
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

            # PARAM2 Distinguished Name of the OU where the computer will get password reset
            [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
                HelpMessage = 'Distinguished Name of the OU where the computer will get password reset',
                Position = 1)]
            [ValidateNotNullOrEmpty()]
            [String]
            $LDAPpath,

            # PARAM3 SWITCH If present, the access rule will be removed.
            [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
                HelpMessage = 'If present, the access rule will be removed.',
                Position = 2)]
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

        } #end Begin

        Process {
            <#
                ACE number: 1
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : ListChildren, ReadProperty, Delete, GenericWrite, WriteDacl
                  AccessControlType : Allow
                         ObjectType : GuidNULL
                    InheritanceType : All
                InheritedObjectType : GuidNULL
                        IsInherited = False
            #>
            $parameters = @{
                Id                    = $PSBoundParameters['Group']
                LDAPPath              = $PSBoundParameters['LDAPpath']
                AdRight               = 'ListChildren', 'ReadProperty', 'Delete', 'GenericWrite', 'WriteDacl'
                AccessControlType     = 'Allow'
                ObjectType            = $Constants.GuidNULL
                AdSecurityInheritance = 'All'
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
             ActiveDirectoryRightst : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : msDS-GroupManagedServiceAccount [ClassSchema]
                    InheritanceType : All
                InheritedObjectType : GuidNULL
                        IsInherited = False
            #>
            $parameters = @{
                Id                    = $PSBoundParameters['Group']
                LDAPPath              = $PSBoundParameters['LDAPpath']
                AdRight               = 'CreateChild', 'DeleteChild'
                AccessControlType     = 'Allow'
                ObjectType            = $Variables.GuidMap['msDS-GroupManagedServiceAccount']
                AdSecurityInheritance = 'All'
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
             ActiveDirectoryRightst : CreateChild, DeleteChild
                  AccessControlType : Allow
                         ObjectType : msDS-GroupManagedServiceAccount [ClassSchema]
                    InheritanceType : All
                InheritedObjectType : GuidNULL
                        IsInherited = False
            #>
            $parameters = @{
                Id                    = $PSBoundParameters['Group']
                LDAPPath              = $PSBoundParameters['LDAPpath']
                AdRight               = 'ReadProperty', 'WriteProperty'
                AccessControlType     = 'Allow'
                ObjectType            = $Variables.GuidMap['msDS-GroupManagedServiceAccount']
                AdSecurityInheritance = 'All'
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
                 ActiveDirectoryRightst : CreateChild, DeleteChild
                      AccessControlType : Allow
                             ObjectType : applicationVersion [ClassSchema]
                        InheritanceType : Descendents
                    InheritedObjectType : msDS-ManagedServiceAccount [ClassSchema]
                            IsInherited = False
            #>
            $parameters = @{
                Id                    = $PSBoundParameters['Group']
                LDAPPath              = $PSBoundParameters['LDAPpath']
                AdRight               = 'CreateChild', 'DeleteChild'
                AccessControlType     = 'Allow'
                ObjectType            = $Variables.GuidMap['applicationVersion']
                AdSecurityInheritance = 'Descendents'
                InheritedObjectType   = $Variables.GuidMap['msDS-GroupManagedServiceAccount']
            }
            # Check if RemoveRule switch is present.
            If($PSBoundParameters['RemoveRule']) {
                # Add the parameter to remove the rule
                $parameters.Add('RemoveRule', $true)
            }
            Set-AclConstructor6 @parameters
        } #end Process

        End {
            Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
            Write-Verbose -Message ''
            Write-Verbose -Message '--------------------------------------------------------------------------------'
            Write-Verbose -Message ''
        } #end END
    }

}

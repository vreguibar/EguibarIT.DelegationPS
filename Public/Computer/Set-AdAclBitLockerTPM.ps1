#Permissions on Computers to access BitLocker and TPM information
function Set-AdAclBitLockerTPM {
    <#
        .Synopsis
            The function will delegate the right to access BitLocker and TPM computer information in an OU
        .DESCRIPTION
            The function will delegate the premission for a group to Modify BitLocker and TPM information of Computer object
        .EXAMPLE
            Set-AdAclBitLockerTPM -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .EXAMPLE
            Set-AdAclBitLockerTPM -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .PARAMETER Group
            [STRING] for the Delegated Group Name
        .PARAMETER LDAPpath
            [STRING] Distinguished Name of the OU where the BitLocker and TPM computer information will be accessed.
        .PARAMETER RemoveRule
            [SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor6                    | EguibarIT.Delegation
                New-GuidObjectHashTable                | EguibarIT.Delegation
        .NOTES
            Version:         1.0
            DateModified:    18/Oct/2016
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

        # PARAM2 Distinguished Name of the OU where the computer ValidateWriteSPN will be set
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where the BitLocker and TPM computer information will be accessed.',
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
        }
    } #end Begin

    Process {
        <#
            ACE number: 1
            --------------------------------------------------------
                  IdentityReference : SELF
             ActiveDirectoryRightst : WriteProperty
                  AccessControlType : Allow
                         ObjectType : msTPM-OwnerInformation [AttributeSchema]
                    InheritanceType : Descendents
                InheritedObjectType : computer [ClassSchema]
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = 'SELF'
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['msTPM-OwnerInformation']
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['computer']
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor6 @parameters

        <#
            ACE number: 2
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : ReadProperty
                  AccessControlType : Allow
                         ObjectType : msTPM-OwnerInformation [AttributeSchema]
                    InheritanceType : Descendents
                InheritedObjectType : computer [ClassSchema]
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'ReadProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['msTPM-OwnerInformation']
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['computer']
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor6 @parameters

        <#
            ACE number: 3
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : GenericAll
             AccessControlType      : Allow
             ObjectType             : GuidNULL
             InheritanceType        : Descendents
             InheritedObjectType    : msFVE-RecoveryInformation [ClassSchema]
             IsInherited            : False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['msFVE-RecoveryInformation']
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor6 @parameters

        <#
            ACENumber              : 4
            IdentityReference      : EguibarIT\XXX
            ActiveDirectoryRightst : ReadProperty, WriteProperty
            AccessControlType      : Allow
            ObjectType             : msTPM-TpmInformationForComputer [AttributeSchema]
            InheritanceType        : Descendents
            InheritedObjectType    : computer [ClassSchema]
            IsInherited            : False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['msTPM-TpmInformationForComputer']
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['computer']
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

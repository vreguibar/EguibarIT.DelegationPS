﻿#Permissions on Computers to access BitLocker and TPM information
function Set-AdAclBitLockerTPM {
    <#
        .Synopsis
            The function will delegate the right to access BitLocker and TPM computer information in an OU
        .DESCRIPTION
            The function will delegate the permission for a group to Modify BitLocker and TPM information of Computer object
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
                Set-AclConstructor6                    | EguibarIT.DelegationPS
                Get-AttributeSchemaHashTable           | EguibarIT.DelegationPS
        .NOTES
            Version:         1.0
            DateModified:    18/Oct/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    Param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        $Group,

        # PARAM2 Distinguished Name of the OU where the computer ValidateWriteSPN will be set
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where the BitLocker and TPM computer information will be accessed.',
            Position = 1)]
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
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
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
        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # $Variables.GuidMap is empty. Call function to fill it up
        Write-Verbose -Message 'Variable $Variables.GuidMap is empty. Calling function to fill it up.'
        Get-AttributeSchemaHashTable

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

    } #end Begin

    Process {
        <#
            ACE number: 1
            --------------------------------------------------------
                  IdentityReference : SELF
             ActiveDirectoryRights  : WriteProperty
                  AccessControlType : Allow
                         ObjectType : msTPM-OwnerInformation [AttributeSchema]
                    InheritanceType : Descendents
                InheritedObjectType : computer [ClassSchema]
                        IsInherited = False
        #>
        $Splat = @{
            Id                    = 'SELF'
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['msTPM-OwnerInformation']
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['computer']
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to msTPM-OwnerInformation?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to msTPM-OwnerInformation?')) {
            Set-AclConstructor6 @Splat
        } #end If

        <#
            ACE number: 2
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights : ReadProperty
                  AccessControlType : Allow
                         ObjectType : msTPM-OwnerInformation [AttributeSchema]
                    InheritanceType : Descendents
                InheritedObjectType : computer [ClassSchema]
                        IsInherited = False
        #>
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'ReadProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['msTPM-OwnerInformation']
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['computer']
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to msTPM-OwnerInformation?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to msTPM-OwnerInformation?')) {
            Set-AclConstructor6 @Splat
        } #end If

        <#
            ACE number: 3
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRights : GenericAll
             AccessControlType      : Allow
             ObjectType             : GuidNULL
             InheritanceType        : Descendents
             InheritedObjectType    : msFVE-RecoveryInformation [ClassSchema]
             IsInherited            : False
        #>
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['msFVE-RecoveryInformation']
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to msFVE-RecoveryInformation?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to msFVE-RecoveryInformation?')) {
            Set-AclConstructor6 @Splat
        } #end If

        <#
            ACENumber              : 4
            IdentityReference      : EguibarIT\XXX
            ActiveDirectoryRights : ReadProperty, WriteProperty
            AccessControlType      : Allow
            ObjectType             : msTPM-TpmInformationForComputer [AttributeSchema]
            InheritanceType        : Descendents
            InheritedObjectType    : computer [ClassSchema]
            IsInherited            : False
        #>
        $Splat = @{
            Id                    = $CurrentGroup
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['msTPM-TpmInformationForComputer']
            AdSecurityInheritance = 'Descendents'
            InheritedObjectType   = $Variables.GuidMap['computer']
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions to msTPM-TpmInformationForComputer?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permissions to msTPM-TpmInformationForComputer?')) {
            Set-AclConstructor6 @Splat
        } #end If
    } #end Process

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0} on {1}' -f $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0} on {1}' -f $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath'])
        } #end If-Else

        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'delegating BitLocker & TPM.'
        )
        Write-Verbose -Message $txt
    } #end END
}

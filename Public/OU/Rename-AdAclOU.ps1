﻿Function Rename-AdAclOU {
    <#
        .Synopsis
            Set delegation to Rename OU
        .DESCRIPTION
            Configures the container (OU) to delegate the permissions to a group so it can Rename organizational unit objects.
        .EXAMPLE
            Rename-AdAclOU "SL_ADRight" "OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .EXAMPLE
            Rename-AdAclOU -Group "SL_ADRight" -LDAPpath "OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .PARAMETER Group
            [STRING] Identity of the group getting the delegation.
        .PARAMETER LDAPpath
            [STRING] Distinguished Name of the OU that can be Changed
        .PARAMETER RemoveRule
            [SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor6                    | EguibarIT.Delegation
                Get-AttributeSchemaHashTable                | EguibarIT.Delegation
        .NOTES
            Version:         1.1
            DateModified:    17/Oct/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Group Name which will get the delegation',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        [String]
        $Group,

        #PARAM2 Distinguished Name of the OU were the groups can be changed
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU that can be Changed',
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
        [Hashtable]$Splat = [hashtable]::New()

        Write-Verbose -Message 'Checking variable $Variables.GuidMap. In case is empty a function is called to fill it up.'
            Get-AttributeSchemaHashTable
    } #end Begin

    Process {
        <#
            ACE number: 1
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : ReadProperty, WriteProperty
                  AccessControlType : Allow
                         ObjectType : distinguishedName
                    InheritanceType : All
                InheritedObjectType : organizationalUnit [ClassSchema]
                        IsInherited = False
        #>
        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['distinguishedName']
            AdSecurityInheritance = 'All'
            InheritedObjectType   = $Variables.GuidMap['organizationalUnit']
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for distinguishedName?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for distinguishedName?')) {
            Set-AclConstructor6 @Splat
        } #end If

        <#
            ACE number: 2
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : ReadProperty, WriteProperty
                  AccessControlType : Allow
                         ObjectType : cn
                    InheritanceType : All
                InheritedObjectType : organizationalUnit [ClassSchema]
                        IsInherited = False
        #>
        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['cn']
            AdSecurityInheritance = 'All'
            InheritedObjectType   = $Variables.GuidMap['organizationalUnit']
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for cn?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for cn?')) {
            Set-AclConstructor6 @Splat
        } #end If

        <#
            ACE number: 3
            --------------------------------------------------------
                  IdentityReference : XXX
             ActiveDirectoryRightst : ReadProperty, WriteProperty
                  AccessControlType : Allow
                         ObjectType : name
                    InheritanceType : All
                InheritedObjectType : organizationalUnit [ClassSchema]
                        IsInherited = False
        #>
        $Splat = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['name']
            AdSecurityInheritance = 'All'
            InheritedObjectType   = $Variables.GuidMap['organizationalUnit']
        }
        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {

            if ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove permissions for name?')) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            } #end If
        } #end If

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Delegate the permisssions for name?')) {
            Set-AclConstructor6 @Splat
        } #end If

    } # end Process

    End {

        if ($RemoveRule) {
            Write-Verbose ('Permissions removal process completed for group: {0} on {1}' -f $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath'])
        } else {
            Write-Verbose ('Permissions delegation process completed for group: {0} on {1}' -f $PSBoundParameters['Group'], $PSBoundParameters['LDAPpath'])
        } #end If-Else

        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished rename OU."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}

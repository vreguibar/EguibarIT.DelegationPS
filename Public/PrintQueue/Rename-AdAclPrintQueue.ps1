﻿Function Rename-AdAclPrintQueue {
    <#
        .Synopsis
            Set delegation to Rename PrintQueue
        .DESCRIPTION
            Configures the container (OU) to delegate the permissions to a group so it can Rename PrintQueue objects.
        .EXAMPLE
            Rename-AdAclPrintQueue -Group "SL_PrinterRight" -LDAPpath "OU=Printers,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .EXAMPLE
            Rename-AdAclPrintQueue -Group "SL_PrinterRight" -LDAPpath "OU=Printers,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .PARAMETER Group
            [STRING] for the Delegated Group Name
        .PARAMETER LDAPpath
            [STRING] Distinguished Name of the OU that can be Changed
        .PARAMETER RemoveRule
            [SWITCH] If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor6                    | EguibarIT.Delegation
                New-GuidObjectHashTable                | EguibarIT.Delegation
        .NOTES
            Version:         1.1
            DateModified:    17/Oct/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]

    param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Group Name which will get the delegation',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference','Identity','Trustee','GroupID')]
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
             ActiveDirectoryRightst : ReadProperty, WriteProperty
                  AccessControlType : Allow
                         ObjectType : distinguishedName
                    InheritanceType : All
                InheritedObjectType : printQueue [ClassSchema]
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['distinguishedName']
            AdSecurityInheritance = 'All'
            InheritedObjectType   = $Variables.GuidMap['PrintQueue']
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
             ActiveDirectoryRightst : ReadProperty, WriteProperty
                  AccessControlType : Allow
                         ObjectType : cn
                    InheritanceType : All
                InheritedObjectType : printQueue [ClassSchema]
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['cn']
            AdSecurityInheritance = 'All'
            InheritedObjectType   = $Variables.GuidMap['PrintQueue']
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
             ActiveDirectoryRightst : ReadProperty, WriteProperty
                  AccessControlType : Allow
                         ObjectType : name
                    InheritanceType : All
                InheritedObjectType : printQueue [ClassSchema]
                        IsInherited = False
        #>
        $parameters = @{
            Id                    = $PSBoundParameters['Group']
            LDAPPath              = $PSBoundParameters['LDAPpath']
            AdRight               = 'ReadProperty', 'WriteProperty'
            AccessControlType     = 'Allow'
            ObjectType            = $Variables.GuidMap['name']
            AdSecurityInheritance = 'All'
            InheritedObjectType   = $Variables.GuidMap['PrintQueue']
        }
        # Check if RemoveRule switch is present.
        If($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $parameters.Add('RemoveRule', $true)
        }
        Set-AclConstructor6 @parameters
    } # end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating central OU."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}

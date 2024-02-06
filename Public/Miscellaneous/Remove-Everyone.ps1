# Remove Everyone ('S-1-1-0') Built-In Group from object
Function Remove-Everyone {
    <#
        .SYNOPSIS
            Remove the built-in group EVERYONE from the given object.
        .DESCRIPTION
            Remove the built-in group EVERYONE from the given object
        .EXAMPLE
            Remove-Everyone -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .PARAMETER LDAPpath
            [String] Distinguished Name of the object (or container) where the permissions are going to be removed.
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor5                    | EguibarIT.Delegation
        .NOTES
            Version:         1.1
            DateModified:    29/Sep/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]

    param (
        # PARAM1 STRING for the Object Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the object (or container) where the permissions are going to be removed.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPpath
    )

    begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
        $parameters = $null
    } #end Begin

    process {
        <#
            ACENumber              : 2
            IdentityReference      : Everyone
            ActiveDirectoryRightst : ReadProperty, WriteProperty, GenericExecute
            AccessControlType      : Allow
            ObjectType             : GuidNULL
            InheritanceType        : All
            InheritedObjectType    : GuidNULL
            IsInherited            : False
        #>
        $parameters = @{
            Id                    = 'EVERYONE'
            LDAPPath              = $PSBoundParameters['LDAPPath']
            AdRight               = 'ReadProperty', 'WriteProperty', 'GenericExecute'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.GuidNULL
            AdSecurityInheritance = 'All'
            RemoveRule            = $true
        }
        Set-AclConstructor5 @parameters
    } #end Process

    end {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}

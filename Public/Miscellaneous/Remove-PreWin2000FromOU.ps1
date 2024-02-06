Function Remove-PreWin2000FromOU {
    <#
        .SYNOPSIS
            Remove Pre-Windows 2000 Compatible Access built-in group from the specified OU.
        .DESCRIPTION
            Remove the built-in group Pre-Windows 2000 Compatible Access from the specified OU.
        .EXAMPLE
            Remove-PreWin2000FromOU -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .PARAMETER LDAPpath
            [String] Distinguished Name of the object
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor6                    | EguibarIT.Delegation
                New-GuidObjectHashTable                | EguibarIT.Delegation
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
            HelpMessage = 'Object Distinguished Name',
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

    process {
        try {
            # Remove inheritance, otherwise is not possible to remove
            Set-AdInheritance -LDAPPath $PSBoundParameters['LDAPpath'] -RemoveInheritance $true -RemovePermissions $true

            # Remove the List Children
            $parameters = @{
                Id                    = 'Pre-Windows 2000 Compatible Access'
                LDAPPath              = $PSBoundParameters['LDAPpath']
                AdRight               = 'ListChildren'
                AccessControlType     = 'Allow'
                ObjectType            = $Constants.guidNull
                AdSecurityInheritance = 'All'
                RemoveRule            = $true
            }
            Set-AclConstructor5 @parameters

            # Remove inetOrgPerson
            $parameters = @{
                Id                    = 'Pre-Windows 2000 Compatible Access'
                LDAPPath              = $PSBoundParameters['LDAPpath']
                AdRight               = 'ReadProperty', 'ListObject', 'ReadControl'
                AccessControlType     = 'Allow'
                ObjectType            = $Constants.guidNull
                AdSecurityInheritance = 'Descendents'
                InheritedObjectType   = $Variables.GuidMap['inetOrgPerson']
                RemoveRule            = $true
            }
            Set-AclConstructor6 @parameters

            # Remove Group
            $parameters = @{
                Id                    = 'Pre-Windows 2000 Compatible Access'
                LDAPPath              = $PSBoundParameters['LDAPpath']
                AdRight               = 'ReadProperty', 'ListObject', 'ReadControl'
                AccessControlType     = 'Allow'
                ObjectType            = $Constants.guidNull
                AdSecurityInheritance = 'Descendents'
                InheritedObjectType   = $Variables.GuidMap['group']
                RemoveRule            = $true
            }
            Set-AclConstructor6 @parameters

            # Remove User
            $parameters = @{
                Id                    = 'Pre-Windows 2000 Compatible Access'
                LDAPPath              = $PSBoundParameters['LDAPpath']
                AdRight               = 'ReadProperty', 'ListObject', 'ReadControl'
                AccessControlType     = 'Allow'
                ObjectType            = $Constants.guidNull
                AdSecurityInheritance = 'Descendents'
                InheritedObjectType   = $Variables.GuidMap['user']
                RemoveRule            = $true
            }
            Set-AclConstructor6 @parameters
        } catch { throw }
    } #end Process

    end {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}

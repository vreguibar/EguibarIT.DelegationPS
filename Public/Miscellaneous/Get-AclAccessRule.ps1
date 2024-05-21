Function Get-AclAccessRule {
    <#
        .Synopsis
            Helper function to show Access Rules of given object
        .DESCRIPTION
            This function will retrive and display the Access Rules of the given object.
        .EXAMPLE
            Get-AclAccessRule "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .EXAMPLE
            Get-AclAccessRule -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .EXAMPLE
            Get-AclAccessRule "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" "Pre-Windows 2000 Compatible Access"
        .EXAMPLE
            Get-AclAccessRule -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -SearchBy "Pre-Windows 2000 Compatible Access"
        .EXAMPLE
            $Splat = @{
                LDAPPath = "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
                SearchBy = "Pre-Windows 2000 Compatible Access"
            }
            Get-AclAccessRule @Splat
        .PARAMETER LDAPpath
            [String] Distinguished Name of the object
        .PARAMETER SearchBy
            [String] The identity to filter ACE
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-ACL                                | Microsoft.PowerShell.Security
                Set-Location                           | Microsoft.PowerShell.Management
                Convert-GUIDToName                     | EguibarIT.DelegationPS
        .NOTES
            Version:         1.1
            DateModified:    17/Oct/2022
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Low')]
    [OutputType([System.Collections.ArrayList])]

    param
    (
        # PARAM1 LDAP path to the object to get the ACL
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the object',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ })]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        # PARAM1 Search by Identity Reference
        [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'The identity to filter ACE',
            Position = 1)]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        [String]
        $SearchBy
    )
    Begin {

        $error.clear()

        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        Import-Module -Name ActiveDirectory -Verbose:$false

        Set-Location -Path AD:\

        $result = [System.Collections.ArrayList]::New()

    } #end Begin
    Process {
        If ($PSBoundParameters['searchBy']) {
            $AclAccess = Get-Acl -Path $PSBoundParameters['LDAPpath'] |
            Select-Object -ExpandProperty Access |
            Where-Object -FilterScript {
                $_.IdentityReference -match $PSBoundParameters['searchBy']
            }

            Write-Verbose -Message ('{0}    ACE (Access Control Entry)  Filtered By: {1}' -f $Constants.NL, $PSBoundParameters['searchBy'])

        } else {
            $AclAccess = Get-Acl -Path $PSBoundParameters['LDAPpath'] | Select-Object -ExpandProperty Access
            Write-Verbose -Message ('{0}    ACE (Access Control Entry) ' -f $Constants.NL)

        }

        Write-Verbose -Message ('    Total ACE found : {0}' -f $AclAccess.count)
        Write-Verbose -Message '------------------------------------------------------------'

        $AceCount = 1
        foreach ($entry in $AclAccess) {

            $ACLResult = [PSCustomObject]@{
                ACENumber             = $AceCount
                Id                    = $entry.IdentityReference
                LDAPpath              = $LDAPpath
                AdRight               = $entry.ActiveDirectoryRights
                AccessControlType     = $entry.AccessControlType
                ObjectType            = (Convert-GUIDToName -guid $entry.ObjectType -Verbose:$false)
                AdSecurityInheritance = $entry.InheritanceType
                InheritedObjectType   = (Convert-GUIDToName -guid $entry.InheritedObjectType -Verbose:$false)
                IsInherited           = $entry.IsInherited
            }
            [void]$result.Add($ACLResult)

            $AceCount++
        } #end Foreach
    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished getting ACL."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''

        Set-Location -Path $env:HOMEDRIVE\

        Return $result
    } #end End
}

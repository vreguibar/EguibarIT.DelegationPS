# Remove AUTHENTICATED USERS ('S-1-5-11') Built-In Group from object
Function Remove-AuthUser {
    <#
        .SYNOPSIS
            Remove Authenticated Users built-in group from the given object.
        .DESCRIPTION
            Remove the built-in group Authenticated Users from the given object
        .EXAMPLE
            Remove-AuthUser -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .PARAMETER LDAPpath
            [String] Distinguished Name of the object (or container) where the permissions are going to be removed.
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AclConstructor5                    | EguibarIT.DelegationPS
        .NOTES
            Version:         1.1
            DateModified:    29/Sep/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param (
        # PARAM1 STRING for the Object Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the object (or container) where the permissions are going to be removed.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ }, ErrorMessage = 'DistinguishedName provided is not valid! Please Check.')]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath
    )

    Begin {

        $txt = ($Variables.HeaderDelegation -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Get 'Authenticated Users' group by SID
        $AuthenticatedUsers = Get-AdGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-11' }

    } #end Begin

    Process {
        $Splat = @{
            Id                    = $AuthenticatedUsers
            LDAPPath              = $PSBoundParameters['LDAPPath']
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'All'
            RemoveRule            = $true
        }
        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove "AUTHENTICATED USERS"?')) {
            Set-AclConstructor5 @Splat
        } #end If
    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'removing AUTHENTICATED USERS.'
        )
        Write-Verbose -Message $txt
    } #end END
}

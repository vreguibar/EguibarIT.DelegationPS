# Remove Account Operators Built-In Group from object
Function Remove-AccountOperator {
    <#
        .SYNOPSIS
            Remove Account Operators built-in group from the given object.
        .DESCRIPTION
            Remove the built-in group Account Operators from the given object.
        .EXAMPLE
            Remove-AccountOperator -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
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

    begin {

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

        # Get 'Account Operators' group by SID
        $AccountOperators = Get-AdGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-548' }

    } #end Begin

    process {
        $Splat = @{
            Id                    = $AccountOperators
            LDAPPath              = $PSBoundParameters['LDAPPath']
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'All'
            RemoveRule            = $true
        }

        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove "Account Operators"?')) {
            Set-AclConstructor5 @Splat
        } #end If
    } #end Process

    end {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'removing Account Operators.'
        )
        Write-Verbose -Message $txt
    } #end END
}

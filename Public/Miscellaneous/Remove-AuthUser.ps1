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
    [OutputType([void])]

    param (
        # PARAM1 STRING for the Object Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the object (or container) where the permissions are going to be removed.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New()

    } #end Begin

    Process {
        $Splat = @{
            Id                    = 'AUTHENTICATED USERS'
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
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) removed AUTHENTICATED USERS."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}

Function Remove-PreWin2000 {
    <#
        .SYNOPSIS
            Remove Pre-Windows 2000 Compatible Access built-in group from the given object.
        .DESCRIPTION
            Remove the built-in group Pre-Windows 2000 Compatible Access from the given object
        .EXAMPLE
            Remove-PreWin2000 -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
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

    begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
        [Hashtable]$Splat = [hashtable]::New()

    } #end Begin

    process {
        $Splat = @{
            Id                    = 'Pre-Windows 2000 Compatible Access'
            LDAPPath              = $PSBoundParameters['LDAPPath']
            AdRight               = 'GenericAll'
            AccessControlType     = 'Allow'
            ObjectType            = $Constants.guidNull
            AdSecurityInheritance = 'All'
            RemoveRule            = $true
        }

        If ($PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove "Pre-Windows 2000 Compatible Access"?')) {
            Set-AclConstructor5 @Splat
        } #end If
    } #end Process

    end {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) removed Pre-Windows 2000 Compatible Access."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}

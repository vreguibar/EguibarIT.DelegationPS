Function Set-AdInheritance {
    <#
        .Synopsis
            The function will Set/Clear Inheritance of
            an object
        .DESCRIPTION
            The function will Set/Clear Inheritance of
            an object
        .EXAMPLE
            Set-AdInheritance -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveInheritance $true -RemovePermissions $false
        .EXAMPLE
            Set-AdInheritance "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" $true $false
        .PARAMETER LDAPpath
            [String] Distinguished Name of the object
        .PARAMETER RemoveInheritance
        .PARAMETER RemovePermissions
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
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'The Delegated Group Name',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPpath,

        # PARAM2 Bool for the IsProtected parameter
        [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present inheritance of object will be removed.',
            Position = 1)]
        [bool]
        $RemoveInheritance,

        # PARAM3 Bool for the preserveInheritance parameter
        [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present the permissions from the parent object are copied to the object.',
            Position = 2)]
        [bool]
        $RemovePermissions
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        Set-Location -Path 'AD:\'
    }

    Process {
        try {
            $acl = Get-Acl -Path ('AD:\{0}' -f $PSBoundParameters['LDAPPath'])

            # First value will set/Remove the inheritance Check-Box
            #     set the value of the IsProtected parameter (1) to TRUE, the inheritance checkbox will be cleared.
            #     If we set it to FALSE, the checkbox will become checked
            # Second value will "copy" (true)  or "remove" (false) the permissions
            #     The "preserveInheritance" parameter (2) only has an effect when we uncheck the inheritance checkbox  (IsProtected = TRUE).
            #     If we set preserveInheritance to TRUE then the permissions from the parent object are copied to the object.
            #     It has the same effect as clicking "Add".
            #     If "preserverInheritance" is set to FALSE, it has the same effect as clicking �Remove�
            $acl.SetAccessRuleProtection($PSBoundParameters['RemoveInheritance'], $PSBoundParameters['RemovePermissions'])

            If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['LDAPPath'], 'Set/Remove Inheritance and permissions?')) {
                Set-Acl -AclObject $acl -Path ('AD:\{0}' -f $PSBoundParameters['LDAPPath'])
            } #end If
        } catch {
            throw
        }
    } #end Process

    End {
        Set-Location -Path $env:HOMEDRIVE\

        Write-Verbose -Message "Function $($MyInvocation.InvocationName) setting Inheritance and permissions."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}

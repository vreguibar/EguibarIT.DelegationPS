# https://github.com/p0w3rsh3ll/SCManager/blob/master/SCManager.psm1
Function Get-SCManagerPermission {
    <#
        .SYNOPSIS
            Get the current SC Manager permissions

        .DESCRIPTION
            Get the current SC Manager permissions

        .EXAMPLE
            Get-SCManagerPermission

        .EXAMPLE
        Get-SCManagerPermission |
        Select Transl*,Secu*,AccessMask,AceType | ft -AutoSize

        .PARAMETER Computer
            Remote computer to execute the commands.

    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]
    [OutputType([void])]

    Param(
        # PARAM0 STRING for the Delegated Group Name
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remote computer to execute the commands..',
            Position = 0)]
        [Alias('Host', 'PC', 'Server', 'HostName')]
        [String]
        $Computer
    )

    Begin {
        $error.clear()

        $txt = ($Variables.HeaderDelegation -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports
        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false

        ##############################
        # Variables Definition

        $Permission = $null
        $MySDDL = $null

    } #end Begin

    Process {

        # get current 'Service Control Manager (SCM)' acl in SDDL format
        Write-Verbose -Message 'Get current "Service Control Manager (SCM)" acl in SDDL format'

        $MySDDL = if ($Computer) {
            (& $ServiceControlCmd.Definition @("\\$Computer", 'sdshow', 'scmanager'))[1]
        } else {
           ( & $ServiceControlCmd.Definition @('sdshow', 'scmanager'))[1]
        } #end If-Else

        Write-Verbose -Message ('Retrieved SDDL: {0}' -f $MySDDL)

        # Build the Common Security Descriptor from SDDL
        $Permission = [System.Security.AccessControl.CommonSecurityDescriptor]::New($true, $False, $MySDDL)

        Foreach ($Dacl in $Permission.DiscretionaryAcl) {
            $Dacl | Add-Member -MemberType ScriptProperty -Name TranslatedSID -Value ({
                    $this.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value
                }) -PassThru
        } #end Foreach

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'showing Service Control Manager (SCM) access.'
        )
        Write-Verbose -Message $txt
    } #end END
}

﻿# https://github.com/p0w3rsh3ll/SCManager/blob/master/SCManager.psm1
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

        $txt = ($constants.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports
        Import-Module -Name ActiveDirectory -SkipEditionCheck -Verbose:$false | Out-Null

        ##############################
        # Variables Definition

        $Permission = $null
        $MySDDL = $null

    } #end Begin

    Process {

        # get current 'Service Control Manager (SCM)' acl in SDDL format
        Write-Verbose -Message 'Get current "Service Control Manager (SCM)" acl in SDDL format'

        $Splat = @{
            ScriptBlock = { ((& (Get-Command "$($env:SystemRoot)\System32\sc.exe") @('sdshow', 'scmanager'))[1]) }
        }
        If ($Computer) {
            $Splat.Add('ComputerName', $Computer)
        } #end If
        $MySDDL = Invoke-Command @Splat

        # Build the Common Security Descriptor from SDDL
        $Permission = [System.Security.AccessControl.CommonSecurityDescriptor]::New($true, $False, $MySDDL)

        Foreach ($Dacl in $Permission.DiscretionaryAcl) {
            $Dacl | Add-Member -MemberType ScriptProperty -Name TranslatedSID -Value ({
                    $this.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value
                }) -PassThru
        } #end Foreach

    } #end Process

    End {
        $txt = ($Constants.Footer -f $MyInvocation.InvocationName,
            'showing Service Control Manager (SCM) access.'
        )
        Write-Verbose -Message $txt
    } #end END
}

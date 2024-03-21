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

#>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]
    [OutputType([void])]

    Param()
    Begin {
        $error.clear()

        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        $Permission = $null

        $HT = @{
            Path        = 'HKLM:\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder\Security'
            ErrorAction = 'Stop'
        }
    } #end Begin

    Process {
        $Permission = $(
            try {
                # Get permission from Registry
                New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList (
                    $true,
                    $false,
                    ((Get-ItemProperty -Name Security @HT).Security),
                    0
                )
            } catch [System.Management.Automation.ItemNotFoundException] {
                # Registry does not exist. Query SC.exe to get permissions
                New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList (
                    $true,
                    $false,
                    ((& (Get-Command "$($env:SystemRoot)\System32\sc.exe") @('sdshow', 'scmanager'))[1])
                )
            } catch {
                Write-Warning -Message "Failed to read Security in the registry because $($_.Exception.Message)"
            } #end Try-Catch
        )

        # Iterate DACLs
        Foreach ($Dacl in $Permission.DiscretionaryAcl) {
            $Dacl | Add-Member -MemberType ScriptProperty -Name TranslatedSID -Value ({
                    $this.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value
                }) -PassThru
        } #end Foreach
    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished checking Service Control Manager (SCM) access."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
}

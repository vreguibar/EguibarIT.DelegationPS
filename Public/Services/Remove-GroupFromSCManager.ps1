Function Remove-GroupFromSCManager {
    <#
        .Synopsis
            Removes a group from the Service Control Manager (SCM) ACL.

        .DESCRIPTION
            This function removes a specified group from the Service Control Manager (SCM) ACL.

        .EXAMPLE
            Remove-GroupFromSCManager -Group "EguibarIT\SG_AdAdmins"

        .EXAMPLE
            Remove-GroupFromSCManager -Group "EguibarIT\SG_AdAdmins" -Computer DC1

        .EXAMPLE
            $Splat = @{
                Group = "EguibarIT\SG_AdAdmins"
                Verbose = $true
            }
           Remove-GroupFromSCManager @Splat

        .PARAMETER Group
            Specifies the group to be removed from the SCM ACL.

        .PARAMETER Computer
            Remote computer to execute the commands.

        .NOTES
            This function relies on SC.exe located at $env:SystemRoot\System32\

        .NOTES
            Version:         1.0
            DateModified:    22/Mar/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    Param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        $Group,

        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remote computer to execute the commands..',
            Position = 1)]
        [Alias('Host', 'PC', 'Server', 'HostName')]
        [String]
        $Computer
    )

    Begin {

        $error.clear()

        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        Import-MyModule -Name ActiveDirectory -Verbose:$false

        ##############################
        # Variables Definition

        [Hashtable]$Splat = [hashtable]::New()

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

        # Get group SID
        $GroupSID = $CurrentGroup.SID.Value

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
        Write-Verbose -Message 'Build the Common Security Descriptor from SDDL'
        $Permission = [System.Security.AccessControl.CommonSecurityDescriptor]::New($true, $False, $MySDDL)

        # Search the DACL for the given Group SID. Delete if found!
        Write-Verbose -Message 'Search the DACL for the given Group SID. Delete if found!'
        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Remove group from SCM?')) {

            $Permission.DiscretionaryAcl | Where-Object { $_.SecurityIdentifier.Value -eq $GroupSID } | ForEach-Object {
                try {
                    $Permission.DiscretionaryAcl.RemoveAccessSpecific(
                        $_.AceType,
                        $_.SecurityIdentifier,
                        $_.AccessMask,
                        0,
                        0
                    )
                    Write-Verbose -Message ('Successfully removed {0} for {1}' -f $_.AceType, $PSBoundParameters['Group'])
                } catch {
                    Write-Warning -Message "Failed to remove access because $($_.Exception.Message)"
                } #end Try-Catch
            } #end $Permission

            # Commit changes
            Write-Verbose -Message 'Commit changes.'
            try {
                # Get SDDL
                Write-Verbose -Message 'Get SDDL from Common Security Descriptor.'
                $sddl = $Permission.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)

                # Make sure computer has 'sc.exe':
                $ServiceControlCmd = Get-Command "$env:SystemRoot\system32\sc.exe"

                If ($Computer) {
                    & $ServiceControlCmd.Definition @("\\$Computer", 'sdset', 'scmanager', "$sddl")
                } else {
                    & $ServiceControlCmd.Definition @('sdset', 'scmanager', "$sddl")
                }
                Write-Verbose -Message 'Successfully set binary ACL in the registry' -Verbose
            } catch {
                Write-Warning -Message "Failed to set Security in the registry because $($_.Exception.Message)"
            } #end Try-Catch
        } #end If

    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished removing Service Control Manager (SCM) access."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}

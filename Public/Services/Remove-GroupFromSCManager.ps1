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
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        $Group,

        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remote computer to execute the commands..',
            Position = 1)]
        [Alias('Host', 'PC', 'Server', 'HostName')]
        [String]
        $Computer
    )

    Begin {

        Set-StrictMode -Version Latest

        $txt = ($Variables.HeaderDelegation -f
            (Get-Date).ToString('dd/MMM/yyyy'),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false

        ##############################
        # Variables Definition

        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Verify Group exist and return it as Microsoft.ActiveDirectory.Management.AdGroup
        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

        # Get group SID
        $GroupSID = $CurrentGroup.SID.Value

        # Make sure computer has 'sc.exe'. sc.exe supports remoting by giving \\computername
        $ServiceControlCmd = Get-Command "$env:SystemRoot\system32\sc.exe"

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
                    Write-Error -Message "Failed to remove access because $($_.Exception.Message)"
                    #Get-ErrorDetail -ErrorRecord $_
                } #end Try-Catch
            } #end $Permission

            # Commit changes
            Write-Verbose -Message 'Commit changes.'
            try {
                # Get SDDL
                Write-Verbose -Message 'Get SDDL from Common Security Descriptor.'
                $sddl = $Permission.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)

                If ($Computer) {
                    & $ServiceControlCmd.Definition @("\\$Computer", 'sdset', 'scmanager', "$sddl")
                } else {
                    & $ServiceControlCmd.Definition @('sdset', 'scmanager', "$sddl")
                }
                Write-Verbose -Message 'Successfully set binary ACL in the registry'
            } catch {
                Write-Error -Message ('Failed to set Security in the registry because {0}' -f $_.Exception.Message)
                #Get-ErrorDetail -ErrorRecord $_
            } #end Try-Catch
        } #end If

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'removing Service Control Manager (SCM) access.'
        )
        Write-Verbose -Message $txt
    } #end END
}

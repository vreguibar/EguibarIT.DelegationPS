Add-Type @'
  [System.FlagsAttribute]
  public enum ServiceAccessFlags : uint
  {
      QueryConfig          = 1,
      ChangeConfig         = 2,
      QueryStatus          = 4,
      EnumerateDependents  = 8,
      Start                = 16,
      Stop                 = 32,
      PauseContinue        = 64,
      Interrogate          = 128,
      UserDefinedControl   = 256,
      Delete               = 65536,
      ReadControl          = 131072,
      WriteDac             = 262144,
      WriteOwner           = 524288,
      AllAccess            = 983551,
      Synchronize          = 1048576,
      AccessSystemSecurity = 16777216,
      GenericAll           = 268435456,
      GenericExecute       = 536870912,
      GenericWrite         = 1073741824,
      GenericRead          = 2147483648,
  }
'@

Function Add-GroupToSCManager {
    <#
        .Synopsis
            Adds a group to the Service Control Manager (SCM) ACL.

        .DESCRIPTION
            This function adds a specified group to the Service Control Manager (SCM) ACL with specified permissions.

        .EXAMPLE
            Add-GroupToSCManager -Group "SG_AdAdmins"

        .EXAMPLE
            Add-GroupToSCManager -Group "SG_AdAdmins" -computer DC1

        .EXAMPLE
            $Splat = @{
                Group    = "SG_AdAdmins"
                Computer = DC1
                Verbose  = $true
            }
            Add-GroupToSCManager @Splat

        .PARAMETER Group
            Specifies the group to be added to the SCM ACL.

        .PARAMETER Computer
            Remote computer to execute the commands.

        .NOTES
            This function relies on SC.exe located at $env:SystemRoot\System32\

        .NOTES
            Version:         1.0
            DateModified:    20/Mar/2024
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
        [String]
        $Group,

        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remote computer to execute the commands.',
            Position = 1)]
        [Alias('Host', 'PC', 'Server', 'HostName', 'ComputerName')]
        [String]
        $Computer
    )

    Begin {

        $error.clear()

        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        [Hashtable]$Splat = [hashtable]::New()

        # Get group SID
        $GroupSID = (Get-ADGroup -Identity $PSBoundParameters['Group']).SID.Value

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

        # Add new DACL
        Write-Verbose -Message 'Add new DACL'
        If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], 'Add group from SCM?')) {

            try {
                $Permission.DiscretionaryAcl.AddAccess(
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    [System.Security.Principal.SecurityIdentifier]"$($GroupSID)",
                    131093, # int accessMask
                    [System.Security.AccessControl.InheritanceFlags]::None,
                    [System.Security.AccessControl.PropagationFlags]::None
                )
                # Combine the desired flags instead of 131093
                # $combinedFlags = [ServiceAccessFlags]::QueryConfig -bor [ServiceAccessFlags]::QueryStatus -bor [ServiceAccessFlags]::Start -bor [ServiceAccessFlags]::ReadControl

                Write-Verbose -Message ('Successfully Added {0} for {1}' -f $_.AceType, $PSBoundParameters['Group'])
            } catch {
                Write-Warning -Message "Failed to add access because $($_.Exception.Message)"
            }

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
                Write-Verbose -Message 'Successfully set ACL in Service Control Manager'
            } catch {
                Write-Warning -Message "Failed to set Security in the registry because $($_.Exception.Message)"
            } #end Try-Catch
        } #end If

    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished adding Service Control Manager (SCM) access."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
} # End Function

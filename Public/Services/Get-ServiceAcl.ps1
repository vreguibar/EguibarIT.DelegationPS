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
      AllAccess            = 983551
      Synchronize          = 1048576,
      AccessSystemSecurity = 16777216,
      GenericAll           = 268435456,
      GenericExecute       = 536870912,
      GenericWrite         = 1073741824,
      GenericRead          = 2147483648,
  }
'@

# Service Security and Access Rights
# https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights?ranMID=46133&ranEAID=wizKxmN8no4&ranSiteID=wizKxmN8no4-IeZwvoh43192JZrq0xrt5A&epi=wizKxmN8no4-IeZwvoh43192JZrq0xrt5A&irgwc=1&OCID=AIDcmm549zy227_aff_7791_1243925&tduid=(ir__uh6z3jtojwkfby6tfvng2qx9i22xd0oxvpg0khbx00)(7791)(1243925)(wizKxmN8no4-IeZwvoh43192JZrq0xrt5A)()&irclickid=_uh6z3jtojwkfby6tfvng2qx9i22xd0oxvpg0khbx00

function Get-ServiceAcl {
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Medium', DefaultParameterSetName = 'ByName')]
    [OutputType([void])]

    param(

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Name of the service. For example BITS',
            ParameterSetName = 'ByName',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('ServiceName', 'Service')]
        [string[]]
        $Name,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Display Name of the service. For example "Background Intelligent Transfer Service"',
            ParameterSetName = 'ByDisplayName',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('ServiceDisplayName')]
        [string[]]
        $DisplayName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remote computer to execute the commands.',
            Position = 1)]
        [Alias('Host', 'PC', 'Server', 'HostName', 'ComputerName')]
        [string]
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


        If (-Not $Computer) {
            Write-Verbose -Message 'No computer name provided. Trying the local computer instead.'
            $Computer = $env:COMPUTERNAME
        }

        # If display name was provided, get the actual service name:
        switch ($PSCmdlet.ParameterSetName) {
            'ByDisplayName' {
                Write-Verbose -Message 'Query the service(s) using DisplayName'
                $Name = Get-Service -DisplayName $DisplayName -ComputerName $Computer -ErrorAction Stop |
                Select-Object -ExpandProperty Name
            }
        } #end Switch

        # Make sure computer has 'sc.exe':
        $ServiceControlCmd = Get-Command "$env:SystemRoot\system32\sc.exe"
        if (-not $ServiceControlCmd) {
            throw "Could not find $env:SystemRoot\system32\sc.exe command!"
        } #end If

    } #end Begin

    Process {

        Write-Verbose -Message 'Getting the services'
        # Get-Service does the work looking up the service the user requested:

        $CurrentService = Invoke-Command -ComputerName $Computer -ScriptBlock { param($service) Get-Service -Name $service } -ArgumentList $PSBoundParameters['Name']

        ForEach ($_ in $CurrentService) {

            # We might need this info in catch block, so store it to a variable
            $CurrentName = $_.Name

            Write-Verbose -Message 'Getting SDDL'
            # Get SDDL using sc.exe
            $Sddl = & $ServiceControlCmd.Definition "\\$Computer" sdshow "$CurrentName" | Where-Object { $_ }

            try {

                Write-Verbose -Message 'Get the DACL from the SDDL string'
                $Dacl = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)

            } catch {
                Write-Warning "Couldn't get security descriptor for service '$Current': $Sddl"
                return
            } #end Try-Catch

            # Create the custom object with the note properties
            $CustomObject = New-Object -TypeName PSObject -Property ([ordered] @{ Name = $_.Name
                    Dacl                                                               = $Dacl
                })

            # Add the 'Access' property:
            $CustomObject | Add-Member -MemberType ScriptProperty -Name Access -Value {
                $this.Dacl.DiscretionaryAcl | ForEach-Object {
                    $CurrentDacl = $_

                    try {

                        $IdentityReference = $CurrentDacl.SecurityIdentifier.Translate([System.Security.Principal.NTAccount])
                        Write-Verbose -Message 'Translated SID to account'

                    } catch {
                        $IdentityReference = $CurrentDacl.SecurityIdentifier.Value
                    }

                    New-Object -TypeName PSObject -Property ([ordered] @{
                            ServiceRights     = [ServiceAccessFlags] $CurrentDacl.AccessMask
                            AccessControlType = $CurrentDacl.AceType
                            IdentityReference = $IdentityReference
                            IsInherited       = $CurrentDacl.IsInherited
                            InheritanceFlags  = $CurrentDacl.InheritanceFlags
                            PropagationFlags  = $CurrentDacl.PropagationFlags
                        })
                }
            }

            # Add 'AccessToString' property that mimics a property of the same name from normal Get-Acl call
            $CustomObject | Add-Member -MemberType ScriptProperty -Name AccessToString -Value {
                $this.Access | ForEach-Object {
                    '{0} {1} {2}' -f $_.IdentityReference, $_.AccessControlType, $_.ServiceRights
                } | Out-String
            }

        } #end Foreach

    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished getting Service ACL."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''

        return $CustomObject
    } #end End
}

Add-Type @'
  [System.FlagsAttribute]
  public enum ServiceAccessFlags : uint
  {
      QueryConfig = 1,
      ChangeConfig = 2,
      QueryStatus = 4,
      EnumerateDependents = 8,
      Start = 16,
      Stop = 32,
      PauseContinue = 64,
      Interrogate = 128,
      UserDefinedControl = 256,
      Delete = 65536,
      ReadControl = 131072,
      WriteDac = 262144,
      WriteOwner = 524288,
      Synchronize = 1048576,
      AccessSystemSecurity = 16777216,
      GenericAll = 268435456,
      GenericExecute = 536870912,
      GenericWrite = 1073741824,
      GenericRead = 2147483648,
      AllAccess = 983551
  }
'@

# Service Security and Access Rights
# https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights?ranMID=46133&ranEAID=wizKxmN8no4&ranSiteID=wizKxmN8no4-IeZwvoh43192JZrq0xrt5A&epi=wizKxmN8no4-IeZwvoh43192JZrq0xrt5A&irgwc=1&OCID=AIDcmm549zy227_aff_7791_1243925&tduid=(ir__uh6z3jtojwkfby6tfvng2qx9i22xd0oxvpg0khbx00)(7791)(1243925)(wizKxmN8no4-IeZwvoh43192JZrq0xrt5A)()&irclickid=_uh6z3jtojwkfby6tfvng2qx9i22xd0oxvpg0khbx00

function Get-ServiceAcl {
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param(

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Name of the service. For example BITS',
            ParameterSetName = 'ByName',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Name,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Display Name of the service. For example "Background Intelligent Transfer Service"',
            ParameterSetName = 'ByDisplayName',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $DisplayName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Name of the computer to get the service from.',
            Position = 1)]
        [string]
        $ComputerName = $env:COMPUTERNAME
    )

    Begin {
        # If display name was provided, get the actual service name:
        switch ($PSCmdlet.ParameterSetName) {
            'ByDisplayName' {
                $Name = Get-Service -DisplayName $DisplayName -ComputerName $ComputerName -ErrorAction Stop |
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
        # Get-Service does the work looking up the service the user requested:
        Get-Service -Name $Name | ForEach-Object {

            # We might need this info in catch block, so store it to a variable
            $CurrentName = $_.Name

            # Get SDDL using sc.exe
            $Sddl = & $ServiceControlCmd.Definition "\\$ComputerName" sdshow "$CurrentName" | Where-Object { $_ }

            try {
                # Get the DACL from the SDDL string
                $Dacl = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
            } catch {
                Write-Warning "Couldn't get security descriptor for service '$CurrentName': $Sddl"
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

        } #end Get-Service
    } #end Process

    End {
        $CustomObject
    } #end End
}

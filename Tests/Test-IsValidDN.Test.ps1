BeforeAll {
    # Import module and function
    $ProjectPath = Split-Path -Parent -Path (Split-Path -Parent -Path $PSScriptRoot)
    $ModuleName = Split-Path -Leaf -Path $ProjectPath
    $ModulePath = Join-Path -Path $ProjectPath -ChildPath $ModuleName

    Import-Module -Name $ModulePath -Force
    . (Join-Path -Path $ProjectPath -ChildPath 'Private\Test-IsValidDN.ps1')
}

Describe 'Test-IsValidDN' {
    Context 'Parameter Validation' {
        It 'Should have mandatory ObjectDN parameter' {
            Get-Command Test-IsValidDN | Should -HaveParameter ObjectDN -Mandatory
        }

        It 'Should accept pipeline input' {
            (Get-Command Test-IsValidDN).Parameters['ObjectDN'].Attributes.ValueFromPipeline | Should -Be $true
        }

        It 'Should have proper aliases' {
            Get-Alias -Definition Test-IsValidDN -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
            $param = (Get-Command Test-IsValidDN).Parameters['ObjectDN']
            $param.Aliases | Should -Contain 'DN'
            $param.Aliases | Should -Contain 'DistinguishedName'
        }
    }

    Context 'Functionality - Valid DNs' {
        BeforeAll {
            $validDNs = @(
                'CN=Test User,DC=domain,DC=com',
                'OU=Users,DC=domain,DC=com',
                'CN=John Doe,OU=Sales,DC=contoso,DC=com',
                'CN=Service Account,OU=Service Accounts,OU=IT,DC=corp,DC=local'
            )
        }

        It 'Should return true for valid DN "<_>"' -TestCases $validDNs {
            param($dn)
            Test-IsValidDN -ObjectDN $dn | Should -Be $true
        }

        It 'Should process multiple valid DNs through pipeline' {
            $results = $validDNs | Test-IsValidDN
            $results | Should -HaveCount $validDNs.Count
            $results | Should -Not -Contain $false
        }
    }

    Context 'Functionality - Invalid DNs' {
        BeforeAll {
            $invalidDNs = @(
                'Invalid DN',
                'DC=only,one,part',
                'CN=NoClosing,DC=domain',
                'CN==Double,DC=equals',
                '',
                $null
            )
        }

        It 'Should return false for invalid DN "<_>"' -TestCases $invalidDNs {
            param($dn)
            { Test-IsValidDN -ObjectDN $dn } | Should -Throw
        }

        It 'Should handle multiple invalid DNs through pipeline without breaking' {
            $results = $validDNs + $invalidDNs | Test-IsValidDN -ErrorAction SilentlyContinue
            $results | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Error Handling' {
        It 'Should write error for null input' {
            { Test-IsValidDN -ObjectDN $null } | Should -Throw
        }

        It 'Should write error for empty string' {
            { Test-IsValidDN -ObjectDN '' } | Should -Throw
        }

        It 'Should write error for whitespace-only string' {
            { Test-IsValidDN -ObjectDN '   ' } | Should -Throw
        }
    }

    Context 'Performance' {
        BeforeAll {
            $largeDNSet = 1..1000 | ForEach-Object {
                "CN=User$_,OU=Users,DC=domain,DC=com"
            }
        }

        It 'Should process 1000 DNs in under 5 seconds' {
            $execution = Measure-Command {
                $largeDNSet | Test-IsValidDN | Out-Null
            }
            $execution.TotalSeconds | Should -BeLessThan 5
        }
    }

    Context 'Verbose Output' {
        It 'Should provide verbose output when requested' {
            $output = Test-IsValidDN -ObjectDN 'CN=Test,DC=domain,DC=com' -Verbose 4>&1
            $output | Should -Not -BeNullOrEmpty
            $output.Message | Should -Match 'DN validation'
        }
    }
}

AfterAll {
    # Cleanup if needed
    Remove-Module -Name $ModuleName -Force -ErrorAction SilentlyContinue
}

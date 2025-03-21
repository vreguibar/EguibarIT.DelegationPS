# Get-ExtendedRightHashTable.Tests.ps1
BeforeAll {
    # Import module and function
    # Uncomment and modify path as needed
    # Import-Module -Name EguibarIT.DelegationPS

    # Mock variables and constants
    $Global:Variables = @{
        configurationNamingContext = 'CN=Configuration,DC=contoso,DC=com'
        ExtendedRightsMap          = $null
        HeaderDelegation           = 'Date: {0} - Function: {1} - Parameters: {2}'
        FooterDelegation           = 'Function: {0} - Result: {1}'
    }

    $Global:Constants = @{
        guidNull = '00000000-0000-0000-0000-000000000000'
    }

    # Mock functions
    Mock Get-ADObject {
        @(
            [PSCustomObject]@{
                DisplayName = 'User-Force-Change-Password'
                rightsGuid  = [byte[]](0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01)
            },
            [PSCustomObject]@{
                DisplayName = 'Send-As'
                rightsGuid  = [byte[]](0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x01, 0x01, 0x02, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02)
            },
            [PSCustomObject]@{
                DisplayName = 'Receive-As'
                rightsGuid  = [byte[]](0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x01, 0x01, 0x03, 0x00, 0x01, 0x01, 0x01, 0x01, 0x03)
            }
        )
    }

    Mock Get-ADRootDSE {
        [PSCustomObject]@{
            configurationNamingContext = 'CN=Configuration,DC=contoso,DC=com'
        }
    }
}

Describe 'Get-ExtendedRightHashTable Tests' {
    BeforeEach {
        # Reset ExtendedRightsMap before each test
        $Global:Variables.ExtendedRightsMap = $null
    }

    Context 'Parameter Validation' {
        It 'Should have Force parameter that accepts switch input' {
            (Get-Command Get-ExtendedRightHashTable).Parameters['Force'].ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It 'Should have Server parameter that accepts string input' {
            (Get-Command Get-ExtendedRightHashTable).Parameters['Server'].ParameterType.Name | Should -Be 'String'
        }
    }

    Context 'Functionality Tests' {
        It 'Should return a hashtable' {
            $result = Get-ExtendedRightHashTable
            $result | Should -BeOfType [System.Collections.Hashtable]
        }

        It 'Should populate Variables.ExtendedRightsMap' {
            Get-ExtendedRightHashTable
            $Global:Variables.ExtendedRightsMap | Should -Not -BeNullOrEmpty
        }

        It 'Should include "All" entry with null GUID' {
            $result = Get-ExtendedRightHashTable
            $result['All'] | Should -Be $Global:Constants.guidNull
        }

        It 'Should call Get-ADObject once when ExtendedRightsMap is empty' {
            Get-ExtendedRightHashTable
            Should -Invoke Get-ADObject -Exactly 1
        }

        It 'Should not call Get-ADObject when ExtendedRightsMap exists and Force is not used' {
            # First call to populate the ExtendedRightsMap
            Get-ExtendedRightHashTable

            # Second call should use existing ExtendedRightsMap
            Get-ExtendedRightHashTable
            Should -Invoke Get-ADObject -Exactly 1
        }

        It 'Should call Get-ADObject when Force is used even if ExtendedRightsMap exists' {
            # First call to populate the ExtendedRightsMap
            Get-ExtendedRightHashTable

            # Second call with Force should rebuild ExtendedRightsMap
            Get-ExtendedRightHashTable -Force
            Should -Invoke Get-ADObject -Exactly 2
        }
    }

    Context 'Custom Server Tests' {
        It 'Should use specified Server in Get-ADObject call' {
            Get-ExtendedRightHashTable -Server 'DC01.contoso.com'
            Should -Invoke Get-ADObject -ParameterFilter { $Server -eq 'DC01.contoso.com' }
        }
    }

    Context 'Error Handling Tests' {
        It 'Should handle Get-ADObject failure' {
            Mock Get-ADObject { throw 'Connection error' }
            { Get-ExtendedRightHashTable } | Should -Throw
        }

        It 'Should handle unauthorized access exceptions' {
            Mock Get-ADObject { throw [System.UnauthorizedAccessException]::new('Access denied') }
            { Get-ExtendedRightHashTable } | Should -Throw
        }

        It 'Should handle empty results and still include "All" entry' {
            Mock Get-ADObject { @() }
            $result = Get-ExtendedRightHashTable
            $result.Count | Should -Be 1
            $result['All'] | Should -Be $Global:Constants.guidNull
        }
    }
}

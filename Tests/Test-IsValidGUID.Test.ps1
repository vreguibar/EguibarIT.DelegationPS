Describe 'Test-IsValidGUID' {
    BeforeAll {
        . $PSCommandPath.Replace('.Tests.ps1', '.ps1')
    }

    Context 'Parameter validation' {
        It 'Should have mandatory ObjectGUID parameter' {
            (Get-Command Test-IsValidGUID).Parameters['ObjectGUID'].Attributes.Mandatory | Should -Be $true
        }
    }

    Context 'Function behavior' {
        It 'Should return true for valid GUID' {
            Test-IsValidGUID -ObjectGUID '550e8400-e29b-41d4-a716-446655440000' | Should -Be $true
        }

        It 'Should return false for invalid GUID' {
            Test-IsValidGUID -ObjectGUID 'invalid-guid' | Should -Be $false
        }

        It 'Should accept pipeline input' {
            '550e8400-e29b-41d4-a716-446655440000' | Test-IsValidGUID | Should -Be $true
        }

        It 'Should throw on null input' {
            { Test-IsValidGUID -ObjectGUID $null } | Should -Throw
        }
    }
}

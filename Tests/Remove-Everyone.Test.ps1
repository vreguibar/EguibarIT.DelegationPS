Describe 'Remove-Everyone' {
    BeforeAll {
        # Mock dependencies
        Mock Set-AclConstructor5 { }
        Mock Test-IsValidDN { $true }
    }

    Context 'Input Validation' {
        It 'Should accept valid DN' {
            { Remove-Everyone -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -Force } |
                Should -Not -Throw
        }

        It 'Should process pipeline input' {
            'OU=Test,DC=EguibarIT,DC=local' | Remove-Everyone -Force
            Should -Invoke Set-AclConstructor5 -Times 1
        }

        It 'Should validate DN format' {
            Mock Test-IsValidDN { $false }
            { Remove-Everyone -LDAPPath 'Invalid DN' -Force } |
                Should -Throw
        }
    }

    Context 'ShouldProcess' {
        It 'Should respect -WhatIf' {
            Remove-Everyone -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -WhatIf
            Should -Invoke Set-AclConstructor5 -Times 0
        }
    }
}

Describe 'Set-AdInheritance' {
    BeforeAll {
        # Mock ACL object
        $mockAcl = @{
            SetAccessRuleProtection = { }
        }

        Mock Get-Acl { $mockAcl }
        Mock Set-Acl { }
        Mock Test-IsValidDN { $true }
        Mock Set-Location { }
        Mock Get-Location { 'C:' }
    }

    Context 'Parameter Validation' {
        It 'Should require LDAPpath parameter' {
            { Set-AdInheritance } | Should -Throw
        }

        It 'Should validate LDAPpath format' {
            Mock Test-IsValidDN { $false }
            { Set-AdInheritance -LDAPPath 'Invalid DN' } | Should -Throw
        }

        It 'Should accept pipeline input' {
            { 'OU=Test,DC=EguibarIT,DC=local' | Set-AdInheritance } | Should -Not -Throw
        }
    }

    Context 'Function Execution' {
        It 'Should process valid inputs' {
            Set-AdInheritance -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -RemoveInheritance $true -Force
            Should -Invoke Get-Acl -Times 1
            Should -Invoke Set-Acl -Times 1
        }

        It 'Should respect WhatIf' {
            Set-AdInheritance -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -WhatIf
            Should -Invoke Set-Acl -Times 0
        }
    }

    Context 'Error Handling' {
        It 'Should handle Get-Acl failures' {
            Mock Get-Acl { throw 'Access Denied' }
            { Set-AdInheritance -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -Force } | Should -Throw
        }

        It 'Should handle Set-Acl failures' {
            Mock Set-Acl { throw 'Permission Denied' }
            { Set-AdInheritance -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -Force } | Should -Throw
        }
    }
}

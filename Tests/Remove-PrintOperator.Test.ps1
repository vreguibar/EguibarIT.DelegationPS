Describe 'Remove-PrintOperator' {
    BeforeAll {
        # Mock dependencies
        Mock Get-ADGroup {
            [PSCustomObject]@{
                DistinguishedName = 'CN=Print Operators,CN=Builtin,DC=EguibarIT,DC=local'
                SID               = 'S-1-5-32-550'
            }
        }
        Mock Set-AclConstructor5 { }
        Mock Test-IsValidDN { $true }
        Mock Get-AttributeSchemaHashTable { }
        Mock Write-Error { }
    }

    Context 'Parameter Validation' {
        It 'Should require LDAPpath parameter' {
            { Remove-PrintOperator } | Should -Throw
        }

        It 'Should validate LDAPpath format' {
            Mock Test-IsValidDN { $false }
            { Remove-PrintOperator -LDAPPath 'Invalid DN' } | Should -Throw
        }

        It 'Should process pipeline input' {
            { 'OU=Test,DC=EguibarIT,DC=local' | Remove-PrintOperator -Force } | Should -Not -Throw
        }
    }

    Context 'Function Execution' {
        It 'Should process valid inputs' {
            Remove-PrintOperator -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -Force
            Should -Invoke Set-AclConstructor5 -Times 1
        }

        It 'Should respect WhatIf' {
            Remove-PrintOperator -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -WhatIf
            Should -Invoke Set-AclConstructor5 -Times 0
        }
    }

    Context 'Error Handling' {
        It 'Should handle missing Print Operators group' {
            Mock Get-ADGroup { $null }
            Remove-PrintOperator -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -Force
            Should -Invoke Write-Error -Times 1
        }

        It 'Should handle Set-AclConstructor5 failures' {
            Mock Set-AclConstructor5 { throw 'Access Denied' }
            Remove-PrintOperator -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -Force
            Should -Invoke Write-Error -Times 1
        }
    }
}

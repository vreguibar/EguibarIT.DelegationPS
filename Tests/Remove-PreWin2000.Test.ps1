Describe 'Remove-PreWin2000' {
    BeforeAll {
        # Mock dependencies
        Mock Get-ADGroup {
            [PSCustomObject]@{
                DistinguishedName = 'CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=EguibarIT,DC=local'
                SID               = 'S-1-5-32-554'
            }
        }
        Mock Set-AclConstructor5 { }
        Mock Test-IsValidDN { $true }
        Mock Write-Error { }
    }

    Context 'Parameter Validation' {
        It 'Should require LDAPpath parameter' {
            { Remove-PreWin2000 } | Should -Throw
        }

        It 'Should validate LDAPpath format' {
            Mock Test-IsValidDN { $false }
            { Remove-PreWin2000 -LDAPPath 'Invalid DN' } | Should -Throw
        }

        It 'Should process pipeline input' {
            { 'OU=Test,DC=EguibarIT,DC=local' | Remove-PreWin2000 -Force } | Should -Not -Throw
        }
    }

    Context 'Function Execution' {
        It 'Should process valid inputs' {
            Remove-PreWin2000 -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -Force
            Should -Invoke Set-AclConstructor5 -Times 1
        }

        It 'Should respect WhatIf' {
            Remove-PreWin2000 -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -WhatIf
            Should -Invoke Set-AclConstructor5 -Times 0
        }
    }

    Context 'Error Handling' {
        It 'Should handle missing Pre-Windows 2000 group' {
            Mock Get-ADGroup { $null }
            Remove-PreWin2000 -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -Force
            Should -Invoke Write-Error -Times 1
        }

        It 'Should handle Set-AclConstructor5 failures' {
            Mock Set-AclConstructor5 { throw 'Access Denied' }
            Remove-PreWin2000 -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -Force
            Should -Invoke Write-Error -Times 1
        }
    }
}

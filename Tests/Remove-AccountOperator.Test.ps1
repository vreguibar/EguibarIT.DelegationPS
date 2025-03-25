Describe 'Remove-AccountOperator' {
    BeforeAll {
        # Mock dependencies
        Mock Get-ADGroup {
            [PSCustomObject]@{
                DistinguishedName = 'CN=Account Operators,CN=Builtin,DC=EguibarIT,DC=local'
                SID               = 'S-1-5-32-548'
            }
        }
        Mock Set-AclConstructor5 { }
        Mock Test-IsValidDN { $true }
    }

    Context 'Input Validation' {
        It 'Should accept valid DN' {
            { Remove-AccountOperator -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -Force } |
                Should -Not -Throw
        }

        It 'Should process pipeline input' {
            'OU=Test,DC=EguibarIT,DC=local' | Remove-AccountOperator -Force
            Should -Invoke Set-AclConstructor5 -Times 1
        }
    }

    Context 'Error Handling' {
        It 'Should handle missing Account Operators group' {
            Mock Get-ADGroup { $null }
            { Remove-AccountOperator -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -Force } |
                Should -Throw
        }
    }
}

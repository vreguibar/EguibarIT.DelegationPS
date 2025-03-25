Describe 'Remove-AuthUser' {
    BeforeAll {
        # Mock dependencies
        Mock Get-ADGroup {
            [PSCustomObject]@{
                DistinguishedName = 'CN=Authenticated Users,CN=Builtin,DC=EguibarIT,DC=local'
                SID               = 'S-1-5-11'
            }
        }
        Mock Set-AclConstructor5 { }
        Mock Test-IsValidDN { $true }
    }

    Context 'Input Validation' {
        It 'Should accept valid DN' {
            { Remove-AuthUser -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -Force } |
                Should -Not -Throw
        }

        It 'Should process pipeline input' {
            'OU=Test,DC=EguibarIT,DC=local' | Remove-AuthUser -Force
            Should -Invoke Set-AclConstructor5 -Times 1
        }
    }

    Context 'Error Handling' {
        It 'Should handle missing Authenticated Users group' {
            Mock Get-ADGroup { $null }
            { Remove-AuthUser -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' -Force } |
                Should -Throw
        }
    }
}

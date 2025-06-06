BeforeAll {
    # Import module
    $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\EguibarIT.DelegationPS.psd1'
    Import-Module -Name $ModulePath -Force
}

Describe 'Set-AclConstructor4 Privilege Key Handling' {
    Context 'When provided a privilege key value' {
        It 'Should gracefully handle privilege key patterns' {
            # Mock functions to isolate test
            Mock -CommandName Get-AdObjectType -ModuleName EguibarIT.DelegationPS -MockWith {
                return 'SeBackupPrivilege'
            }

            # This should not throw but return a warning
            {
                & "$PSScriptRoot\..\Private\Set-AclConstructor4.ps1" `
                    -Id 'TestGroup' `
                    -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' `
                    -AdRight 'GenericAll' `
                    -AccessControlType 'Allow' `
                    -ObjectType '00000000-0000-0000-0000-000000000000' `
                    -WarningAction SilentlyContinue
            } | Should -Not -Throw

            Should -Invoke -CommandName Get-AdObjectType -ModuleName EguibarIT.DelegationPS -Times 1 -Exactly
        }

        It 'Should skip processing when direct privilege key is provided' {
            # This should not throw but return a warning
            {
                & "$PSScriptRoot\..\Private\Set-AclConstructor4.ps1" `
                    -Id 'SeBackupPrivilege' `
                    -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' `
                    -AdRight 'GenericAll' `
                    -AccessControlType 'Allow' `
                    -ObjectType '00000000-0000-0000-0000-000000000000' `
                    -WarningAction SilentlyContinue
            } | Should -Not -Throw
        }
    }

    Context 'When handling SID validation' {
        It 'Should validate SIDs properly' {
            # Mock valid SID response
            Mock -CommandName Get-AdObjectType -ModuleName EguibarIT.DelegationPS -MockWith {
                return 'S-1-5-32-544' # Built-in Administrators
            }

            Mock -CommandName Get-ADObject -ModuleName EguibarIT.DelegationPS -MockWith {
                return @{
                    DistinguishedName = 'OU=Test,DC=EguibarIT,DC=local'
                    ObjectClass       = 'organizationalUnit'
                }
            }

            Mock -CommandName Get-Acl -ModuleName EguibarIT.DelegationPS -MockWith {
                return [System.DirectoryServices.ActiveDirectorySecurity]::new()
            }

            Mock -CommandName Set-Acl -ModuleName EguibarIT.DelegationPS -MockWith { }

            # Use WhatIf to prevent actual changes
            {
                & "$PSScriptRoot\..\Private\Set-AclConstructor4.ps1" `
                    -Id 'TestGroup' `
                    -LDAPPath 'OU=Test,DC=EguibarIT,DC=local' `
                    -AdRight 'GenericAll' `
                    -AccessControlType 'Allow' `
                    -ObjectType '00000000-0000-0000-0000-000000000000' `
                    -WhatIf
            } | Should -Not -Throw

            Should -Invoke -CommandName Get-AdObjectType -ModuleName EguibarIT.DelegationPS -Times 1 -Exactly
        }
    }
}

AfterAll {
    # Clean up
    Remove-Module -Name EguibarIT.DelegationPS -ErrorAction SilentlyContinue
}

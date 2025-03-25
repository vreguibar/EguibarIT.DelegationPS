Describe 'Set-AdAclPromoteDomain' {
    BeforeAll {
        # Mock dependencies
        Mock Get-AdObjectType {
            [PSCustomObject]@{
                ObjectClass = 'group'
                Name        = 'TestGroup'
            }
        }
        Mock Get-ADOrganizationalUnit { $true }
        Mock Set-AclConstructor4 { }
        Mock Set-AclConstructor5 { }
        Mock Set-AdDirectoryReplication { }
        Mock Set-AdAclCreateDeleteSite { }
        Mock Set-AdAclChangeSite { }
    }

    Context 'Parameter Validation' {
        It 'Should require Group parameter' {
            { Set-AdAclPromoteDomain } |
                Should -Throw '*Group*'
        }

        It 'Should require StagingOU parameter' {
            { Set-AdAclPromoteDomain -Group 'TestGroup' } |
                Should -Throw '*StagingOU*'
        }
    }

    Context 'Function Execution' {
        It 'Should process valid inputs' {
            Set-AdAclPromoteDomain -Group 'TestGroup' -StagingOU 'OU=Staging,DC=EguibarIT,DC=local' -Force
            Should -Invoke Get-AdObjectType -Times 1
            Should -Invoke Set-AdDirectoryReplication -Times 1
        }

        It 'Should handle RemoveRule switch' {
            Set-AdAclPromoteDomain -Group 'TestGroup' -StagingOU 'OU=Staging,DC=EguibarIT,DC=local' -RemoveRule -Force
            Should -Invoke Get-AdObjectType -Times 1
        }
    }

    Context 'Error Handling' {
        It 'Should handle invalid group' {
            Mock Get-AdObjectType { throw 'Group not found' }
            { Set-AdAclPromoteDomain -Group 'InvalidGroup' -StagingOU 'OU=Test,DC=EguibarIT,DC=local' } |
                Should -Throw
        }

        It 'Should handle invalid staging OU' {
            Mock Get-ADOrganizationalUnit { $false }
            { Set-AdAclPromoteDomain -Group 'TestGroup' -StagingOU 'Invalid' } |
                Should -Throw
        }
    }
}

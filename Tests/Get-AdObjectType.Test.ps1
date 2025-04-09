Describe 'Get-AdObjectType' {
    BeforeAll {
        # Mock Get-ADObject for different object types
        Mock Get-ADUser {
            return [PSCustomObject]@{
                ObjectClass       = 'user'
                SamAccountName    = 'testuser'
                DistinguishedName = 'CN=testuser,DC=EguibarIT,DC=local'
            }
        }

        Mock Get-ADComputer {
            return [PSCustomObject]@{
                ObjectClass       = 'computer'
                Name              = 'TESTPC'
                DistinguishedName = 'CN=TESTPC,DC=EguibarIT,DC=local'
            }
        }

        Mock Get-ADGroup {
            return [PSCustomObject]@{
                ObjectClass       = 'group'
                Name              = 'TestGroup'
                DistinguishedName = 'CN=TestGroup,DC=EguibarIT,DC=local'
            }
        }

        Mock Get-ADOrganizationalUnit {
            return [PSCustomObject]@{
                ObjectClass       = 'organizationalUnit'
                Name              = 'TestOU'
                DistinguishedName = 'OU=TestOU,DC=EguibarIT,DC=local'
            }
        }

        Mock Get-ADServiceAccount {
            return [PSCustomObject]@{
                ObjectClass       = 'msDS-GroupManagedServiceAccount'
                Name              = 'TestGMSA'
                DistinguishedName = 'CN=TestGMSA,DC=EguibarIT,DC=local'
            }
        }

        Mock Get-ADObject {
            param($Filter)

            if ($Filter.ToString() -match 'testuser') {
                return [PSCustomObject]@{
                    ObjectClass = 'user'
                    Name        = 'testuser'
                }
            } elseif ($Filter.ToString() -match 'TESTPC') {
                return [PSCustomObject]@{
                    ObjectClass = 'computer'
                    Name        = 'TESTPC'
                }
            }
            # Add more object types as needed
        }
    }

    Context 'Parameter validation' {
        It 'Should require mandatory Identity parameter' {
            { Get-AdObjectType } | Should -Throw
        }

        It 'Should accept server parameter' {
            { Get-AdObjectType -Identity 'testuser' -Server 'DC01' } | Should -Not -Throw
        }
    }

    Context 'AD object input' {
        It 'Should handle user object input' {
            $userObj = [PSCustomObject]@{
                ObjectClass    = 'user'
                SamAccountName = 'testuser'
            }
            $result = Get-AdObjectType -Identity $userObj
            $result | Should -Not -BeNullOrEmpty
            $result.ObjectClass | Should -Be 'user'
        }
    }

    Context 'String input formats' {
        It 'Should handle SamAccountName' {
            $result = Get-AdObjectType -Identity 'testuser'
            $result | Should -Not -BeNullOrEmpty
        }

        It 'Should handle DistinguishedName' {
            $result = Get-AdObjectType -Identity 'CN=testuser,DC=EguibarIT,DC=local'
            $result | Should -Not -BeNullOrEmpty
        }

        It 'Should handle GUID' {
            $guid = [System.Guid]::NewGuid().ToString()
            $result = Get-AdObjectType -Identity $guid
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Well-Known SIDs' {
        It 'Should handle Well-Known SID string' {
            $result = Get-AdObjectType -Identity 'S-1-1-0'
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [System.Security.Principal.SecurityIdentifier]
        }

        It 'Should handle Well-Known SID name' {
            $result = Get-AdObjectType -Identity 'Everyone'
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [System.Security.Principal.SecurityIdentifier]
        }
    }

    Context 'Different object types' {
        It 'Should detect user objects' {
            Mock Get-ADObject { return [PSCustomObject]@{ ObjectClass = 'user' } }
            $result = Get-AdObjectType -Identity 'testuser'
            $result.ObjectClass | Should -Be 'user'
        }

        It 'Should detect computer objects' {
            Mock Get-ADObject { return [PSCustomObject]@{ ObjectClass = 'computer' } }
            $result = Get-AdObjectType -Identity 'TESTPC$'
            $result.ObjectClass | Should -Be 'computer'
        }

        It 'Should detect group objects' {
            Mock Get-ADObject { return [PSCustomObject]@{ ObjectClass = 'group' } }
            $result = Get-AdObjectType -Identity 'TestGroup'
            $result.ObjectClass | Should -Be 'group'
        }

        It 'Should detect OU objects' {
            Mock Get-ADObject { return [PSCustomObject]@{ ObjectClass = 'organizationalUnit' } }
            $result = Get-AdObjectType -Identity 'OU=TestOU'
            $result.ObjectClass | Should -Be 'organizationalUnit'
        }

        It 'Should detect GMSA objects' {
            Mock Get-ADObject { return [PSCustomObject]@{ ObjectClass = 'msDS-GroupManagedServiceAccount' } }
            $result = Get-AdObjectType -Identity 'TestGMSA'
            $result.ObjectClass | Should -Be 'msDS-GroupManagedServiceAccount'
        }
    }

    Context 'Pipeline input' {
        It 'Should accept pipeline input' {
            $result = 'testuser' | Get-AdObjectType
            $result | Should -Not -BeNullOrEmpty
        }

        It 'Should accept multiple pipeline inputs' {
            $result = @('testuser1', 'testuser2') | Get-AdObjectType
            $result | Should -HaveCount 2
        }
    }

    Context 'Error handling' {
        It 'Should handle non-existent objects' {
            Mock Get-ADObject { return $null }
            $result = Get-AdObjectType -Identity 'nonexistent'
            $result | Should -BeNullOrEmpty
        }

        It 'Should handle AD errors gracefully' {
            Mock Get-ADObject { throw 'AD Error' }
            $result = Get-AdObjectType -Identity 'error' -ErrorAction SilentlyContinue
            $result | Should -BeNullOrEmpty
        }
    }

    Context 'Server parameter' {
        It 'Should use specified server' {
            $result = Get-AdObjectType -Identity 'testuser' -Server 'DC01'
            Should -Invoke Get-ADObject -ParameterFilter {
                $Server -eq 'DC01'
            }
        }
    }
}

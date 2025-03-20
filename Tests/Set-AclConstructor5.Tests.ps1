# Set-AclConstructor5.Tests.ps1

BeforeAll {
    # Import module (adjust path as needed)
    $ModulePath = Split-Path -Parent $PSScriptRoot
    Import-Module "$ModulePath\EguibarIT.DelegationPS.psd1" -Force

    # Mock variables used by the function
    $script:Variables = @{
        HeaderDelegation = 'Test Header {0} {1} {2}'
        FooterDelegation = 'Test Footer {0} {1}'
        WellKnownSIDs    = @{
            'S-1-5-18'     = 'LOCAL_SYSTEM'
            'S-1-5-32-544' = 'BUILTIN_ADMINISTRATORS'
        }
    }

    # Create test GUID
    $script:TestGuid = [System.Guid]::NewGuid()

    # Mock AD cmdlets and helper functions
    Mock Get-ADObject {
        return [PSCustomObject]@{
            DistinguishedName    = 'CN=TestObject,DC=contoso,DC=com'
            ObjectClass          = 'user'
            nTSecurityDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
        }
    }

    Mock Get-Acl {
        $acl = New-Object System.DirectoryServices.ActiveDirectorySecurity
        return $acl
    }

    Mock Set-Acl { return $true }

    Mock Test-IsValidDN { return $true }

    Mock Get-AdObjectType {
        return [PSCustomObject]@{
            SID         = 'S-1-5-21-3180365091-1677881776-450889589-1001'
            ObjectClass = 'group'
        }
    }
}

Describe 'Set-AclConstructor5' {
    Context 'Parameter validation' {
        It 'Should require mandatory parameters' {
            $command = Get-Command Set-AclConstructor5
            $command.Parameters['Id'].Attributes.Mandatory | Should -Be $true
            $command.Parameters['LDAPpath'].Attributes.Mandatory | Should -Be $true
            $command.Parameters['AdRight'].Attributes.Mandatory | Should -Be $true
            $command.Parameters['AccessControlType'].Attributes.Mandatory | Should -Be $true
            $command.Parameters['ObjectType'].Attributes.Mandatory | Should -Be $true
            $command.Parameters['AdSecurityInheritance'].Attributes.Mandatory | Should -Be $true
        }

        It 'Should validate AdRight parameter' {
            { Set-AclConstructor5 -Id 'TestGroup' -LDAPpath 'DC=contoso,DC=com' -AdRight 'InvalidRight' -AccessControlType 'Allow' -ObjectType $TestGuid -AdSecurityInheritance 'All' } |
                Should -Throw
        }

        It 'Should validate AccessControlType parameter' {
            { Set-AclConstructor5 -Id 'TestGroup' -LDAPpath 'DC=contoso,DC=com' -AdRight 'GenericRead' -AccessControlType 'Invalid' -ObjectType $TestGuid -AdSecurityInheritance 'All' } |
                Should -Throw
        }

        It 'Should validate AdSecurityInheritance parameter' {
            { Set-AclConstructor5 -Id 'TestGroup' -LDAPpath 'DC=contoso,DC=com' -AdRight 'GenericRead' -AccessControlType 'Allow' -ObjectType $TestGuid -AdSecurityInheritance 'Invalid' } |
                Should -Throw
        }
    }

    Context 'Adding access rules' {
        BeforeEach {
            $params = @{
                Id                    = 'TestGroup'
                LDAPpath              = 'DC=contoso,DC=com'
                AdRight               = 'GenericRead'
                AccessControlType     = 'Allow'
                ObjectType            = $TestGuid
                AdSecurityInheritance = 'All'
            }
        }

        It 'Should add new access rule successfully' {
            { Set-AclConstructor5 @params } | Should -Not -Throw
            Should -Invoke Get-ADObject -Times 1
            Should -Invoke Get-Acl -Times 1
            Should -Invoke Set-Acl -Times 1
        }

        It 'Should handle well-known SIDs' {
            $params.Id = 'LOCAL_SYSTEM'
            { Set-AclConstructor5 @params } | Should -Not -Throw
            Should -Invoke Get-AdObjectType -Times 0
        }
    }

    Context 'Removing access rules' {
        BeforeEach {
            $params = @{
                Id                    = 'TestGroup'
                LDAPpath              = 'DC=contoso,DC=com'
                AdRight               = 'GenericRead'
                AccessControlType     = 'Allow'
                ObjectType            = $TestGuid
                AdSecurityInheritance = 'All'
                RemoveRule            = $true
            }
        }

        It 'Should remove existing access rule successfully' {
            { Set-AclConstructor5 @params } | Should -Not -Throw
            Should -Invoke Get-ADObject -Times 1
            Should -Invoke Get-Acl -Times 1
            Should -Invoke Set-Acl -Times 1
        }
    }

    Context 'Error handling' {
        It 'Should handle Get-ADObject errors' {
            Mock Get-ADObject { throw 'AD Error' }

            { Set-AclConstructor5 -Id 'TestGroup' -LDAPpath 'DC=contoso,DC=com' -AdRight 'GenericRead' -AccessControlType 'Allow' -ObjectType $TestGuid -AdSecurityInheritance 'All' } |
                Should -Throw
        }

        It 'Should handle Get-Acl errors' {
            Mock Get-Acl { throw 'ACL Error' }

            { Set-AclConstructor5 -Id 'TestGroup' -LDAPpath 'DC=contoso,DC=com' -AdRight 'GenericRead' -AccessControlType 'Allow' -ObjectType $TestGuid -AdSecurityInheritance 'All' } |
                Should -Throw
        }

        It 'Should handle Set-Acl errors' {
            Mock Set-Acl { throw 'Set ACL Error' }

            { Set-AclConstructor5 -Id 'TestGroup' -LDAPpath 'DC=contoso,DC=com' -AdRight 'GenericRead' -AccessControlType 'Allow' -ObjectType $TestGuid -AdSecurityInheritance 'All' } |
                Should -Throw
        }

        It 'Should handle invalid ObjectType GUID' {
            { Set-AclConstructor5 -Id 'TestGroup' -LDAPpath 'DC=contoso,DC=com' -AdRight 'GenericRead' -AccessControlType 'Allow' -ObjectType 'NotAGuid' -AdSecurityInheritance 'All' } |
                Should -Throw
        }
    }

    Context 'WhatIf support' {
        It 'Should support -WhatIf' {
            $params = @{
                Id                    = 'TestGroup'
                LDAPpath              = 'DC=contoso,DC=com'
                AdRight               = 'GenericRead'
                AccessControlType     = 'Allow'
                ObjectType            = $TestGuid
                AdSecurityInheritance = 'All'
                WhatIf                = $true
            }

            { Set-AclConstructor5 @params } | Should -Not -Throw
            Should -Invoke Set-Acl -Times 0
        }
    }
}

# Set-AclConstructor4.Tests.ps1

BeforeAll {
    # Import module and function
    $ModulePath = Split-Path -Parent $PSScriptRoot
    $FunctionName = (Split-Path -Leaf $PSCommandPath) -replace '.Tests.ps1'

    # Import the function
    . (Join-Path -Path $ModulePath -ChildPath "Private\$FunctionName.ps1")

    # Mock Variables for header/footer
    $Global:Variables = @{
        HeaderDelegation = 'Test Header {0} {1} {2}'
        FooterDelegation = 'Test Footer {0} {1}'
        WellKnownSIDs    = @{
            'S-1-5-32-544' = 'Administrators'
        }
    }

    # Mock dependencies
    Mock Get-ADObject {
        return [PSCustomObject]@{
            DistinguishedName    = 'CN=TestObject,DC=contoso,DC=com'
            ObjectClass          = 'user'
            nTSecurityDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
        }
    }

    Mock Get-AdObjectType {
        return [PSCustomObject]@{
            SID = 'S-1-5-21-1234567890-123456789-123456789-1001'
        }
    }

    Mock Get-Acl {
        $acl = New-Object System.DirectoryServices.ActiveDirectorySecurity
        return $acl
    }

    Mock Set-Acl { return $true }

    Mock Write-Verbose { }
    Mock Write-Debug { }
    Mock Write-Error { }
}

Describe 'Set-AclConstructor4' {
    Context 'Parameter Validation' {
        It 'Should throw when Id is null or empty' {
            { Set-AclConstructor4 -Id $null -LDAPPath 'DC=contoso,DC=com' -AdRight 'CreateChild' -AccessControlType 'Allow' -ObjectType '12345678-1234-1234-1234-123456789012' } |
                Should -Throw
        }

        It 'Should throw when LDAPPath is invalid' {
            { Set-AclConstructor4 -Id 'TestGroup' -LDAPPath 'Invalid\Path' -AdRight 'CreateChild' -AccessControlType 'Allow' -ObjectType '12345678-1234-1234-1234-123456789012' } |
                Should -Throw
        }

        It 'Should throw when AdRight is invalid' {
            { Set-AclConstructor4 -Id 'TestGroup' -LDAPPath 'DC=contoso,DC=com' -AdRight 'InvalidRight' -AccessControlType 'Allow' -ObjectType '12345678-1234-1234-1234-123456789012' } |
                Should -Throw
        }
    }

    Context 'Well-Known SID Handling' {
        It 'Should handle well-known SIDs correctly' {
            $result = Set-AclConstructor4 -Id 'Administrators' -LDAPPath 'DC=contoso,DC=com' -AdRight 'CreateChild' -AccessControlType 'Allow' -ObjectType '12345678-1234-1234-1234-123456789012' -ErrorAction SilentlyContinue
            Should -Invoke Get-ADObject -Times 1
            Should -Invoke Get-Acl -Times 1
            Should -Invoke Set-Acl -Times 1
        }
    }

    Context 'Regular Identity Handling' {
        It 'Should handle regular identities correctly' {
            $result = Set-AclConstructor4 -Id 'TestGroup' -LDAPPath 'DC=contoso,DC=com' -AdRight 'CreateChild' -AccessControlType 'Allow' -ObjectType '12345678-1234-1234-1234-123456789012' -ErrorAction SilentlyContinue
            Should -Invoke Get-AdObjectType -Times 1
            Should -Invoke Get-ADObject -Times 1
            Should -Invoke Get-Acl -Times 1
            Should -Invoke Set-Acl -Times 1
        }
    }

    Context 'ACL Operations' {
        It 'Should add ACL rule when RemoveRule is not specified' {
            $result = Set-AclConstructor4 -Id 'TestGroup' -LDAPPath 'DC=contoso,DC=com' -AdRight 'CreateChild' -AccessControlType 'Allow' -ObjectType '12345678-1234-1234-1234-123456789012' -ErrorAction SilentlyContinue
            Should -Invoke Set-Acl -Times 1
        }

        It 'Should remove ACL rule when RemoveRule is specified' {
            $result = Set-AclConstructor4 -Id 'TestGroup' -LDAPPath 'DC=contoso,DC=com' -AdRight 'CreateChild' -AccessControlType 'Allow' -ObjectType '12345678-1234-1234-1234-123456789012' -RemoveRule -ErrorAction SilentlyContinue
            Should -Invoke Set-Acl -Times 1
        }
    }

    Context 'Error Handling' {
        It 'Should handle Get-ADObject errors gracefully' {
            Mock Get-ADObject { throw 'AD Object Error' }

            { Set-AclConstructor4 -Id 'TestGroup' -LDAPPath 'DC=contoso,DC=com' -AdRight 'CreateChild' -AccessControlType 'Allow' -ObjectType '12345678-1234-1234-1234-123456789012' } |
                Should -Throw
            Should -Invoke Write-Error -Times 1
        }

        It 'Should handle Get-Acl errors gracefully' {
            Mock Get-Acl { throw 'ACL Error' }

            { Set-AclConstructor4 -Id 'TestGroup' -LDAPPath 'DC=contoso,DC=com' -AdRight 'CreateChild' -AccessControlType 'Allow' -ObjectType '12345678-1234-1234-1234-123456789012' } |
                Should -Throw
            Should -Invoke Write-Error -Times 1
        }

        It 'Should handle Set-Acl errors gracefully' {
            Mock Set-Acl { throw 'Set ACL Error' }

            { Set-AclConstructor4 -Id 'TestGroup' -LDAPPath 'DC=contoso,DC=com' -AdRight 'CreateChild' -AccessControlType 'Allow' -ObjectType '12345678-1234-1234-1234-123456789012' } |
                Should -Throw
            Should -Invoke Write-Error -Times 1
        }
    }

    Context 'ObjectType Handling' {
        It 'Should handle string GUID correctly' {
            $result = Set-AclConstructor4 -Id 'TestGroup' -LDAPPath 'DC=contoso,DC=com' -AdRight 'CreateChild' -AccessControlType 'Allow' -ObjectType '12345678-1234-1234-1234-123456789012' -ErrorAction SilentlyContinue
            Should -Invoke Get-ADObject -Times 1
            Should -Invoke Set-Acl -Times 1
        }

        It 'Should handle GUID object correctly' {
            $guid = [System.Guid]::New('12345678-1234-1234-1234-123456789012')
            $result = Set-AclConstructor4 -Id 'TestGroup' -LDAPPath 'DC=contoso,DC=com' -AdRight 'CreateChild' -AccessControlType 'Allow' -ObjectType $guid -ErrorAction SilentlyContinue
            Should -Invoke Get-ADObject -Times 1
            Should -Invoke Set-Acl -Times 1
        }
    }

    Context 'ShouldProcess Handling' {
        It 'Should honor WhatIf parameter' {
            $result = Set-AclConstructor4 -Id 'TestGroup' -LDAPPath 'DC=contoso,DC=com' -AdRight 'CreateChild' -AccessControlType 'Allow' -ObjectType '12345678-1234-1234-1234-123456789012' -WhatIf
            Should -Invoke Set-Acl -Times 0
        }

        It 'Should honor Confirm parameter' {
            Mock $PSCmdlet.ShouldProcess { return $false }
            $result = Set-AclConstructor4 -Id 'TestGroup' -LDAPPath 'DC=contoso,DC=com' -AdRight 'CreateChild' -AccessControlType 'Allow' -ObjectType '12345678-1234-1234-1234-123456789012' -Confirm:$false
            Should -Invoke Set-Acl -Times 0
        }
    }
}

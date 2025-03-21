# Get-AttributeSchemaHashTable.Tests.ps1
BeforeAll {
    # Import module and function
    # Uncomment and modify path as needed
    # Import-Module -Name EguibarIT.DelegationPS

    # Mock variables and constants
    $Global:Variables = @{
        SchemaNamingContext = 'CN=Schema,CN=Configuration,DC=contoso,DC=com'
        GuidMap             = $null
        HeaderDelegation    = 'Date: {0} - Function: {1} - Parameters: {2}'
        FooterDelegation    = 'Function: {0} - Result: {1}'
    }

    $Global:Constants = @{
        guidNull = '00000000-0000-0000-0000-000000000000'
    }

    # Mock functions
    Mock Get-ADObject {
        @(
            [PSCustomObject]@{
                lDAPDisplayName = 'user'
                schemaIDGUID    = [byte[]](0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01)
            },
            [PSCustomObject]@{
                lDAPDisplayName = 'group'
                schemaIDGUID    = [byte[]](0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x01, 0x01, 0x02, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02)
            },
            [PSCustomObject]@{
                lDAPDisplayName = 'computer'
                schemaIDGUID    = [byte[]](0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x01, 0x01, 0x03, 0x00, 0x01, 0x01, 0x01, 0x01, 0x03)
            }
        )
    }

    Mock Get-ADRootDSE {
        [PSCustomObject]@{
            schemaNamingContext = 'CN=Schema,CN=Configuration,DC=contoso,DC=com'
        }
    }
}

Describe 'Get-AttributeSchemaHashTable Tests' {
    BeforeEach {
        # Reset GuidMap before each test
        $Global:Variables.GuidMap = $null
    }

    Context 'Parameter Validation' {
        It 'Should have Force parameter that accepts switch input' {
            (Get-Command Get-AttributeSchemaHashTable).Parameters['Force'].ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It 'Should have SearchBase parameter that accepts string input' {
            (Get-Command Get-AttributeSchemaHashTable).Parameters['SearchBase'].ParameterType.Name | Should -Be 'String'
        }

        It 'Should have Server parameter that accepts string input' {
            (Get-Command Get-AttributeSchemaHashTable).Parameters['Server'].ParameterType.Name | Should -Be 'String'
        }

        It 'Should have Credential parameter that accepts PSCredential input' {
            (Get-Command Get-AttributeSchemaHashTable).Parameters['Credential'].ParameterType.Name | Should -Be 'PSCredential'
        }
    }

    Context 'Functionality Tests' {
        It 'Should return a hashtable' {
            $result = Get-AttributeSchemaHashTable
            $result | Should -BeOfType [System.Collections.Hashtable]
        }

        It 'Should populate Variables.GuidMap' {
            Get-AttributeSchemaHashTable
            $Global:Variables.GuidMap | Should -Not -BeNullOrEmpty
        }

        It 'Should include "All" entry with null GUID' {
            $result = Get-AttributeSchemaHashTable
            $result['All'] | Should -Be $Global:Constants.guidNull
        }

        It 'Should call Get-ADObject once when GuidMap is empty' {
            Get-AttributeSchemaHashTable
            Should -Invoke Get-ADObject -Exactly 1
        }

        It 'Should not call Get-ADObject when GuidMap exists and Force is not used' {
            # First call to populate the GuidMap
            Get-AttributeSchemaHashTable

            # Second call should use existing GuidMap
            Get-AttributeSchemaHashTable
            Should -Invoke Get-ADObject -Exactly 1
        }

        It 'Should call Get-ADObject when Force is used even if GuidMap exists' {
            # First call to populate the GuidMap
            Get-AttributeSchemaHashTable

            # Second call with Force should rebuild GuidMap
            Get-AttributeSchemaHashTable -Force
            Should -Invoke Get-ADObject -Exactly 2
        }
    }

    Context 'Custom Server and Credential Tests' {
        It 'Should use specified Server in Get-ADObject call' {
            Get-AttributeSchemaHashTable -Server 'DC01.contoso.com'
            Should -Invoke Get-ADObject -ParameterFilter { $Server -eq 'DC01.contoso.com' }
        }

        It 'Should use specified Credential in Get-ADObject call' {
            $testCred = New-Object System.Management.Automation.PSCredential ('testuser', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            Get-AttributeSchemaHashTable -Credential $testCred
            Should -Invoke Get-ADObject -ParameterFilter { $Credential -eq $testCred }
        }
    }

    Context 'Error Handling Tests' {
        It 'Should handle Get-ADObject failure' {
            Mock Get-ADObject { throw 'Connection error' }
            { Get-AttributeSchemaHashTable } | Should -Throw
        }

        It 'Should handle unauthorized access exceptions' {
            Mock Get-ADObject { throw [System.UnauthorizedAccessException]::new('Access denied') }
            { Get-AttributeSchemaHashTable } | Should -Throw
        }
    }
}

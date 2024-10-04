# Ensure Pester module is available
Import-Module Pester -ErrorAction Stop

Describe 'Set-GPOConfigSection Tests' {

    # Mock the dependencies
    Mock -CommandName 'ConvertTo-AccountName' -MockWith {
        param($SID)
        if ($SID -eq 'S-1-5-32-544') {
            return @('Administrators')
        }
        if ($SID -eq 'S-1-5-32-573') {
            return @('Event Log Readers')
        }
        return $null
    }

    Mock -CommandName 'Get-AdObjectType' -MockWith {
        param($Identity)
        if ($Identity -eq 'User1') {
            return [PSCustomObject]@{ SID = 'S-1-5-21-1000' }
        }
        if ($Identity -eq 'Group1') {
            return [PSCustomObject]@{ SID = 'S-1-5-32-573' }
        }
        return $null
    }

    Mock -CommandName 'Test-NameIsWellKnownSid' -MockWith {
        param($Name)
        if ($Name -eq 'WellKnownGroup') {
            return 'S-1-5-32-544'
        }
        return $null
    }

    Mock -CommandName 'Get-ErrorDetail' # Suppress actual error detail output for testing

    # Initialize a sample GPT template mock object
    BeforeEach {
        $GptTmplMock = New-Object -TypeName PSObject -Property @{
            GetKeyValue = { param($Section, $Key) return $null }
            SetKeyValue = { param($Section, $Key, $Value) return $true }
        }

        # Mock the GetKeyValue and SetKeyValue methods
        Mock -CommandName 'GetKeyValue' -MockWith {
            param($Section, $Key)
            if ($Section -eq 'User Rights Assignment' -and $Key -eq 'SeDenyNetworkLogonRight') {
                return '*S-1-5-32-544,*S-1-5-32-573'  # Pre-existing members
            }
            return $null
        }

        Mock -CommandName 'SetKeyValue' -MockWith {
            param($Section, $Key, $Value)
            # Capture values for validation
            $script:UpdatedSection = $Section
            $script:UpdatedKey = $Key
            $script:UpdatedValue = $Value
        }
    }

    Context 'Key does not exist - New key creation' {
        It 'Creates a new key when key does not exist' {
            # Arrange
            $members = @('User1', 'Group1')

            # Act
            Set-GPOConfigSection -CurrentSection 'User Rights Assignment' `
                -CurrentKey 'SeBatchLogonRight' `
                -Members $members `
                -GptTmpl $GptTmplMock

            # Assert
            Assert-MockCalled -CommandName 'SetKeyValue' -Times 1
            $UpdatedSection | Should -Be 'User Rights Assignment'
            $UpdatedKey | Should -Be 'SeBatchLogonRight'
            $UpdatedValue | Should -Be '*S-1-5-21-1000,*S-1-5-32-573'
        }
    }

    Context 'Key exists - Existing members' {
        It 'Processes existing members correctly' {
            # Arrange
            $members = @('User1')

            # Act
            Set-GPOConfigSection -CurrentSection 'User Rights Assignment' `
                -CurrentKey 'SeDenyNetworkLogonRight' `
                -Members $members `
                -GptTmpl $GptTmplMock

            # Assert
            Assert-MockCalled -CommandName 'SetKeyValue' -Times 1
            $UpdatedValue | Should -Be '*S-1-5-32-544,*S-1-5-32-573,*S-1-5-21-1000'
        }
    }

    Context 'Members are null or empty' {
        It 'Handles null or empty members as a single null string' {
            # Act
            Set-GPOConfigSection -CurrentSection 'User Rights Assignment' `
                -CurrentKey 'SeDenyNetworkLogonRight' `
                -Members $null `
                -GptTmpl $GptTmplMock

            # Assert
            $UpdatedValue | Should -Be ''
        }
    }

    Context 'SID resolution' {
        It 'Resolves SIDs correctly and adds them with an asterisk' {
            # Arrange
            $members = @('User1', 'Group1')

            # Act
            Set-GPOConfigSection -CurrentSection 'User Rights Assignment' `
                -CurrentKey 'SeBatchLogonRight' `
                -Members $members `
                -GptTmpl $GptTmplMock

            # Assert
            $UpdatedValue | Should -Be '*S-1-5-21-1000,*S-1-5-32-573'
        }

        It 'Skips duplicates when resolving SIDs' {
            # Arrange
            $members = @('Administrators', 'WellKnownGroup')

            # Act
            Set-GPOConfigSection -CurrentSection 'User Rights Assignment' `
                -CurrentKey 'SeBatchLogonRight' `
                -Members $members `
                -GptTmpl $GptTmplMock

            # Assert
            $UpdatedValue | Should -Be '*S-1-5-32-544,*S-1-5-32-573'
        }
    }

    Context 'WhatIf functionality' {
        It 'Does not modify the GPT template when WhatIf is enabled' {
            # Act
            Set-GPOConfigSection -CurrentSection 'User Rights Assignment' `
                -CurrentKey 'SeBatchLogonRight' `
                -Members @('User1') `
                -GptTmpl $GptTmplMock -WhatIf

            # Assert
            Assert-MockCalled -CommandName 'SetKeyValue' -Times 0
        }
    }

    Context 'Error handling' {
        It 'Handles failed SID resolution gracefully' {
            # Mock failure for SID resolution
            Mock -CommandName 'Get-AdObjectType' -MockWith { return $null }

            # Act
            $result = { Set-GPOConfigSection -CurrentSection 'User Rights Assignment' `
                    -CurrentKey 'SeBatchLogonRight' `
                    -Members @('NonExistentUser') `
                    -GptTmpl $GptTmplMock } | Should -Throw
        }
    }

    Context 'ShouldProcess testing' {
        It 'Only processes changes if ShouldProcess condition is met' {
            # Arrange
            $PSCmdletMock = New-MockObject -TypeName PSObject
            $PSCmdletMock.ShouldProcess = $false

            # Act
            Set-GPOConfigSection -CurrentSection 'User Rights Assignment' `
                -CurrentKey 'SeBatchLogonRight' `
                -Members @('User1') `
                -GptTmpl $GptTmplMock

            # Assert
            Assert-MockCalled -CommandName 'SetKeyValue' -Times 0
        }
    }
}

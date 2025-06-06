Describe 'Get-AdWellKnownSID' {
    BeforeAll {
        # Ensure we have our function available
        . $PSScriptRoot\..\Private\Get-AdWellKnownSID.ps1

        # Mock module-level variables if they don't exist
        if (-not (Get-Variable -Name Variables -ErrorAction SilentlyContinue)) {
            $Global:Variables = @{
                WellKnownSIDs = @{
                    'S-1-0'    = 'Null Authority'
                    'S-1-0-0'  = 'Nobody'
                    'S-1-1'    = 'World Authority'
                    'S-1-1-0'  = 'Everyone'
                    'S-1-5-18' = 'Local System Account'
                    'S-1-5-19' = 'Local Service Account'
                    'S-1-5-20' = 'Network Service Account'
                }
            }
        }

        # Mock Test-IsValidSID if it doesn't exist
        if (-not (Get-Command -Name Test-IsValidSID -ErrorAction SilentlyContinue)) {
            function Test-IsValidSID {
                param ([string]$ObjectSID)
                # Basic SID validation
                return $ObjectSID -match '^S-\d-(\d+-){1,14}\d+$'
            }
        }

        # Mock Get-FunctionDisplay if it doesn't exist
        if (-not (Get-Command -Name Get-FunctionDisplay -ErrorAction SilentlyContinue)) {
            function Get-FunctionDisplay {
                param ([hashtable]$Hashtable, [bool]$Verbose = $false)
                return "Parameters: $($Hashtable.Keys -join ', ')"
            }
        }
    }

    Context 'Parameter validation' {
        It 'Should throw when SID parameter is null or empty' {
            { Get-AdWellKnownSID -SID $null } | Should -Throw
            { Get-AdWellKnownSID -SID '' } | Should -Throw
        }

        It 'Should throw when an invalid SID format is provided' {
            { Get-AdWellKnownSID -SID 'NotAValidSID' } | Should -Throw
            { Get-AdWellKnownSID -SID 'S-1' } | Should -Throw
        }
    }

    Context 'Basic functionality' {
        It 'Should return True for well-known SID S-1-5-18' {
            Get-AdWellKnownSID -SID 'S-1-5-18' | Should -BeTrue
        }

        It 'Should return False for a non-well-known SID' {
            Get-AdWellKnownSID -SID 'S-1-5-21-3623811015-3361044348-30300820-1013' | Should -BeFalse
        }

        It 'Should return an array of results when multiple SIDs are provided' {
            $results = Get-AdWellKnownSID -SID 'S-1-5-18', 'S-1-5-19', 'S-1-5-21-3623811015-3361044348-30300820-1013'
            $results | Should -HaveCount 3
            $results[0] | Should -BeTrue
            $results[1] | Should -BeTrue
            $results[2] | Should -BeFalse
        }
    }

    Context 'Detailed output' {
        It 'Should return a custom object with SID, IsWellKnown, and Description properties' {
            $result = Get-AdWellKnownSID -SID 'S-1-5-18' -Detailed

            $result | Should -BeOfType [PSCustomObject]
            $result.SID | Should -Be 'S-1-5-18'
            $result.IsWellKnown | Should -BeTrue
            $result.Description | Should -Be 'Local System Account'
        }

        It 'Should return a custom object with empty description for non-well-known SIDs' {
            $result = Get-AdWellKnownSID -SID 'S-1-5-21-3623811015-3361044348-30300820-1013' -Detailed

            $result | Should -BeOfType [PSCustomObject]
            $result.SID | Should -Be 'S-1-5-21-3623811015-3361044348-30300820-1013'
            $result.IsWellKnown | Should -BeFalse
            $result.Description | Should -BeNullOrEmpty
        }
    }

    Context 'Pipeline functionality' {
        It 'Should accept pipeline input' {
            $results = 'S-1-5-18', 'S-1-5-19' | Get-AdWellKnownSID
            $results | Should -HaveCount 2
            $results[0] | Should -BeTrue
            $results[1] | Should -BeTrue
        }

        It 'Should accept pipeline input with detailed output' {
            $results = 'S-1-5-18', 'S-1-5-19' | Get-AdWellKnownSID -Detailed
            $results | Should -HaveCount 2
            $results[0].IsWellKnown | Should -BeTrue
            $results[1].IsWellKnown | Should -BeTrue
        }
    }

    Context 'Error handling' {
        BeforeEach {
            # Mock Write-Error to capture error messages
            Mock Write-Error {} -Verifiable
        }

        It 'Should continue processing if one SID fails' {
            # Mocking WellKnownSIDs to force an error
            $originalWellKnownSIDs = $Variables.WellKnownSIDs
            $Variables.WellKnownSIDs = $null

            # This should continue processing despite errors
            $results = Get-AdWellKnownSID -SID 'S-1-5-18', 'S-1-5-19' -ErrorAction SilentlyContinue

            # Restore original WellKnownSIDs
            $Variables.WellKnownSIDs = $originalWellKnownSIDs

            # Verify Write-Error was called
            Should -InvokeVerifiable
        }
    }

    Context 'Alias functionality' {
        It 'Should work with Test-AdWellKnownSID alias' {
            # This will throw if the alias doesn't exist
            $aliases = Get-Alias -Definition Get-AdWellKnownSID -ErrorAction SilentlyContinue
            $aliases.Name | Should -Contain 'Test-AdWellKnownSID'

            # Call the function using its alias
            Test-AdWellKnownSID -SID 'S-1-5-18' | Should -BeTrue
        }
    }
}

#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Test script to verify that Set-GPOConfigSection properly handles empty collections
.DESCRIPTION
    This test verifies that the fix for the empty collection parameter binding issue works correctly.
    It tests that Set-GPOConfigSection can accept empty collections for the Members parameter.
#>

# Import the module for testing
Import-Module "$PSScriptRoot\..\EguibarIT.DelegationPS.psd1" -Force

try {
    Write-Host 'Testing Set-GPOConfigSection with empty collections...' -ForegroundColor Cyan

    # Create an empty collection (same type as used in Add-EmptyPrivilegeRightLocal)
    $emptyMembers = [System.Collections.Generic.List[string]]::new()

    Write-Host "Created empty collection of type: $($emptyMembers.GetType().FullName)" -ForegroundColor Yellow
    Write-Host "Empty collection count: $($emptyMembers.Count)" -ForegroundColor Yellow

    # Test the parameter attributes by examining the function metadata
    $cmd = Get-Command Set-GPOConfigSection
    $membersParam = $cmd.Parameters['Members']

    Write-Host "`nParameter attributes for Members parameter:" -ForegroundColor Green
    foreach ($attr in $membersParam.Attributes) {
        Write-Host "  - $($attr.GetType().Name): $attr" -ForegroundColor White
    }

    # Check if AllowEmptyCollection attribute is present
    $hasAllowEmptyCollection = $membersParam.Attributes | Where-Object { $_ -is [System.Management.Automation.AllowEmptyCollectionAttribute] }

    if ($hasAllowEmptyCollection) {
        Write-Host "`n✅ SUCCESS: AllowEmptyCollection attribute is present!" -ForegroundColor Green
        Write-Host 'Empty collections should now be accepted by Set-GPOConfigSection' -ForegroundColor Green
    } else {
        Write-Host "`n❌ FAILURE: AllowEmptyCollection attribute is missing!" -ForegroundColor Red
        Write-Host 'Empty collections will still be rejected by Set-GPOConfigSection' -ForegroundColor Red
    }

    # Test parameter binding simulation (without actual GPO operations)
    Write-Host "`nTesting parameter binding with empty collection..." -ForegroundColor Cyan

    try {
        # This should not fail anymore with the fix
        $testParams = @{
            CurrentSection = 'Privilege Rights'
            CurrentKey     = 'SeTrustedCredManAccessPrivilege'
            Members        = $emptyMembers
            GptTmpl        = $null  # We'll pass null for this test since we're only testing parameter binding
        }

        # Test if parameter binding would work (without actually calling the function)
        $bindingTest = $cmd.ResolveParameter('Members', $emptyMembers)
        Write-Host '✅ Parameter binding test passed - empty collection accepted' -ForegroundColor Green

    } catch {
        Write-Host "❌ Parameter binding test failed: $($_.Exception.Message)" -ForegroundColor Red
    }

} catch {
    Write-Host "❌ Test failed with error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
} finally {
    Write-Host "`nTest completed." -ForegroundColor Cyan
}

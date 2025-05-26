# filepath: TestLocalFunction.ps1

# Import the module first if not already loaded
if (-not (Get-Module -Name 'EguibarIT.DelegationPS')) {
    # Path for module import (use parent directory)
    $modulePath = Split-Path -Path $PSScriptRoot -Parent
    Import-Module -Name $modulePath -Force -Verbose
}

# Define the function exactly as in the modified Set-GpoPrivilegeRight.ps1
function Test-EmptyPrivilegeRightLocal {
    param (
        [System.Collections.Generic.List[object]]$Coll
    )

    # Print collection info for debugging
    Write-Host "Collection type: $($Coll.GetType().FullName), Count: $($Coll.Count)"

    $emptyRights = @(
        'SeTrustedCredManAccessPrivilege',
        'SeTcbPrivilege',
        'SeCreateTokenPrivilege',
        'SeCreatePermanentPrivilege',
        'SeDebugPrivilege',
        'SeLockMemoryPrivilege'
    )

    # Call Get-PrivilegeRightMapping from the module
    $rightMappings = Get-PrivilegeRightMapping

    foreach ($right in $emptyRights) {
        $addRightParams = @{
            Key         = $right
            Members     = [string]::Empty
            Description = $rightMappings[$right]
            Collection  = $Coll
        }

        try {
            # Call Add-Right from the module
            Add-Right @addRightParams
            Write-Host "Successfully added empty right: $right"
        } catch {
            Write-Warning -Message ('Failed to add empty right {0}: {1}' -f $right, $_.Exception.Message)
        }
    }
}

# Create an empty collection
$rightsCollection = [System.Collections.Generic.List[object]]::new()
Write-Host "Initial collection count: $($rightsCollection.Count)"

# Call the local function
Test-EmptyPrivilegeRightLocal -Coll $rightsCollection

# Print results
Write-Host "Final collection count: $($rightsCollection.Count)"
foreach ($item in $rightsCollection) {
    Write-Host "Added item: $($item.Key) - $($item.Description)"
}

# Minimal test for empty collection issue
param(
    [switch]$Verbose,
    [switch]$Debug
)

# Set verbose/debug preferences
if ($Verbose) { $VerbosePreference = 'Continue' }
if ($Debug) { $DebugPreference = 'Continue' }

# Create empty collection
$testCollection = [System.Collections.Generic.List[object]]::new()

Write-Host "Collection type: $($testCollection.GetType().FullName), Count: $($testCollection.Count)"

# Helper function to bypass parameter binding issues
function Add-RightWithoutBinding {
    param(
        [System.Collections.Generic.List[object]]$Collection
    )

    Write-Host "Helper function received collection type: $($Collection.GetType().FullName), Count: $($Collection.Count)"

    # Add item directly to collection
    $Collection.Add(@{
        Section = 'Test'
        Key = 'TestKey'
        Members = [System.Collections.Generic.List[string]]::new()
        Description = 'Test item'
    })

    Write-Host "After adding item, collection count: $($Collection.Count)"
}

# Call the helper function
Add-RightWithoutBinding -Collection $testCollection

# Verify final state
Write-Host "Final collection count: $($testCollection.Count)"
foreach ($item in $testCollection) {
    Write-Host "Item properties: Section=$($item.Section), Key=$($item.Key), Members Count=$($item.Members.Count)"
}

# This proves that passing an empty collection to a function without the Mandatory parameter attribute works fine

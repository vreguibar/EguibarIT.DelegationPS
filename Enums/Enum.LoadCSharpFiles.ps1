# Function to check if a class is already loaded
function Test-ClassExist {
    param(
        [string]$ClassName
    )

    # Try to get the type by its full name
    $type = [Type]::GetType($ClassName, $false, $false)

    # Return true if the type exists, otherwise false
    return [bool]$type
} #end Function








$SCMFlagsCS = [System.IO.File]::ReadAllText("$PSScriptRoot\Enum.SCMFlags.cs")
Add-Type -Language CSharp -TypeDefinition $SCMFlagsCS

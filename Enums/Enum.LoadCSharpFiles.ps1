# Function to check if a Enum is already loaded
function Test-EnumExist {
    <#
        .SYNOPSIS
            Determines whether a .NET enum type is already loaded in the current session.

        .DESCRIPTION
            The Test-EnumExist function checks whether the specified enum type can be resolved
            from the current PowerShell session and returns a bool indicating the result.

        .PARAMETER EnumName
            The enum type name to validate.

        .EXAMPLE
            Test-EnumExist -EnumName 'ServiceControlManagerFlags'

            Returns $true when the enum is available.

        .INPUTS
            System.String

        .OUTPUTS
            System.Boolean

        .NOTES
            Version:         2.0
            DateModified:    23/09/2026
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com
    #>
    param(
        [string]$EnumName
    )

    try {
        [System.Enum]::GetValues([type]$EnumName) | Out-Null
        return [bool]$true
    } catch {
        return [bool]$false
    } #end Try-Catch

} #end Function




# Define the class only if it doesn't already exist
if (-Not (Test-EnumExist ServiceControlManagerFlags)) {
    Write-Verbose -Message 'ServiceControlManagerFlags Enums not loaded. Proceed to load...!'

    $SCMFlagsCS = [System.IO.File]::ReadAllText("$PSScriptRoot\Enum.ServiceControlManagerFlags.cs")
    Add-Type -Language CSharp -TypeDefinition $SCMFlagsCS

} #end If


# Define the class only if it doesn't already exist
if (-Not (Test-EnumExist ServiceControlManagerFlags)) {
    Write-Verbose -Message 'ServiceAccessFlags Enums not loaded. Proceed to load...!'

    $ServiceFlagsCS = [System.IO.File]::ReadAllText("$PSScriptRoot\Enum.ServiceAccessFlags.cs")
    Add-Type -Language CSharp -TypeDefinition $ServiceFlagsCS

} #end If



# Define the class only if it doesn't already exist
if (-Not (Test-EnumExist ServiceControlManagerFlags)) {
    Write-Verbose -Message 'Encoding Enums not loaded. Proceed to load...!'

    $EncodingCS = [System.IO.File]::ReadAllText("$PSScriptRoot\Enum.Encoding.cs")
    Add-Type -Language CSharp -TypeDefinition $EncodingCS

} #end If

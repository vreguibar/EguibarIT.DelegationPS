function Test-MembersProperty {
    <#
        .SYNOPSIS
            Tests and normalizes Members parameter input for consistent processing.

        .DESCRIPTION
            This function validates and normalizes the input Members parameter to ensure it has
            the necessary properties for consistent processing by other functions in the module.

            It handles various input types (null, string, array, collection) and ensures that
            the output is always a strongly-typed System.Collections.Generic.List[string] with
            a Count property, which simplifies processing in calling functions.

            The function provides robust handling for:
            - Null or empty values
            - Single string values
            - Array or collection inputs
            - Mixed types of collection elements

            This is particularly useful in delegation functions where member inputs might come
            from various sources and need consistent handling.

        .PARAMETER Members
            The members object to test and normalize. This parameter accepts:
            - Null value (returns empty list)
            - String (converted to single-item list)
            - Array (converted to list with same elements)
            - Any collection type (elements extracted to list)

            The parameter allows null, empty string, and empty collection values.

        .EXAMPLE
            $result = Test-MembersProperty -Members $null

            Returns an empty List<string> when given a null input.

        .EXAMPLE
            $result = Test-MembersProperty -Members @('User1', 'User2')

            Returns a List<string> containing 'User1' and 'User2' when given an array input.

        .EXAMPLE
            $result = Test-MembersProperty -Members 'SingleUser'

            Returns a List<string> containing just 'SingleUser' when given a string input.

        .INPUTS
            System.Object

            This function accepts any object type as input and processes it accordingly.

        .OUTPUTS
            System.Collections.Generic.List[System.String]

            Always returns a List<string> object, which may be empty if the input was null,
            empty, or contained no valid string representations.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Debug                                ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         2.0
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS

        .COMPONENT
            EguibarIT.DelegationPS

        .ROLE
            Helper

        .FUNCTIONALITY
            Parameter Validation, Collection Processing
    #>

    [CmdletBinding(
        SupportsShouldProcess = $false,
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.Collections.Generic.List[string]])]

    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [object]
        $Members
    )

    # Always create a new List<string> that guarantees having a Count property
    $result = [System.Collections.Generic.List[string]]::new()

    Write-Debug -Message ('Input Members type: {0}' -f $(
            if ($null -eq $Members) {
                'null'
            } else {
                $Members.GetType().FullName
            }
        ))

    # Handle null or empty cases
    if ($null -eq $Members) {

        Write-Debug -Message 'Members parameter is null. Returning empty List<string>'
        return $result

    } #end if

    # Handle string input
    if ($Members -is [string]) {

        if (-not [string]::IsNullOrWhiteSpace($Members)) {

            $result.Add($Members)
            Write-Debug -Message ('Added single string member: {0}' -f $Members)

        } #end if
        return $result

    } #end if

    # Handle array or collection input
    if ($Members -is [Array] -or
        ($Members -is [System.Collections.IEnumerable] -and -not ($Members -is [string]))) {

        foreach ($m in $Members) {

            if ($null -ne $m) {

                $stringValue = $m.ToString()
                if (-not [string]::IsNullOrWhiteSpace($stringValue)) {

                    $result.Add($stringValue)
                    Write-Debug -Message ('Added collection member: {0}' -f $stringValue)

                } #end if
            } #end if
        } #end foreach
        return $result
    } #end if

    # Handle other object types - add as single item if possible
    if ($null -ne $Members) {

        $stringValue = $Members.ToString()
        if (-not [string]::IsNullOrWhiteSpace($stringValue)) {

            $result.Add($stringValue)
            Write-Debug -Message ('Added object as string: {0}' -f $stringValue)
        } #end if
    } #end if

    Write-Debug -Message ('Returning List<string> with {0} items' -f $result.Count)
    return $result
} #end function Test-MembersProperty

function Set-Member {
    <#
    .SYNOPSIS
        Processes members array and converts them to a standardized format.

    .DESCRIPTION
        This function standardizes member objects to a consistent HashSet format.
        It handles null, empty, and various collection types, ensuring consistent
        behavior across different input scenarios.

    .PARAMETER Members
        The members to process, which can be null, empty, a string, or a collection.

    .EXAMPLE
        $result = Set-Member -Members $null
        # Returns a HashSet with a single empty string

    .EXAMPLE
        $result = Set-Member -Members @('User1', 'User2')
        # Returns a HashSet containing User1 and User2

    .NOTES
        This function is optimized to work with the Test-MembersProperty function
        and to provide a consistent format for processing member collections.
    #>
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.Collections.Generic.HashSet[string]])]

    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [object]
        $Members
    )

    Begin {
        Set-StrictMode -Version Latest
        Write-Verbose -Message 'Starting Set-Member function'
    } #end Begin

    Process {

        if ($PSCmdlet.ShouldProcess('Members collection', 'Process and standardize')) {

            # Use Test-MembersProperty to get a standard List<string> with Count property
            $membersList = Test-MembersProperty -Members $Members

            Write-Verbose -Message ('Test-MembersProperty returned: Type={0}' -f $(
                    if ($null -ne $membersList) {
                        $membersList.GetType().FullName
                    } else {
                        'null'
                    }
                ))

            # Log count if membersList exists
            if ($null -ne $membersList) {
                Write-Verbose -Message ('Members count: {0}' -f $membersList.Count)
            } #end if

            # Convert to HashSet for efficient deduplication
            $result = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

            # Add all values from membersList to result
            if ($null -ne $membersList) {

                # Add each member to our result HashSet
                foreach ($member in $membersList) {

                    if (-not [string]::IsNullOrWhiteSpace($member)) {

                        [void]$result.Add($member)
                        Write-Verbose -Message ('Added member to result: {0}' -f $member)

                    } #end If
                } #end foreach
            } #end if

            # If result is empty, add an empty string
            if ($result.Count -eq 0) {

                [void]$result.Add([string]::Empty)
                Write-Verbose -Message 'Members collection is empty. Adding empty string.'

            } #end if

            # Return the HashSet with unique members
            Write-Verbose -Message ('Returning HashSet with {0} members' -f $result.Count)
            return $result
        } #end if ShouldProcess
    } #end Process

    End {
        # Nothing to clean up
    } #end End
} #end function Set-Member

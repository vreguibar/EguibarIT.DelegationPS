function Add-EmptyPrivilegeRightLocal {

    <#
        .SYNOPSIS
            Adds empty privilege rights to the collection without parameter binding issues.

        .DESCRIPTION
            This function adds empty privilege rights to the collection by directly manipulating
            the collection object. It avoids PowerShell parameter binding issues that can occur
            when passing empty collections to functions with [Parameter(Mandatory = $true)].

            The function adds a predefined set of privilege rights with empty member lists to the
            provided collection. If the collection is null, a new collection will be created.

            This is primarily designed as an internal helper function for Group Policy privilege
            right management.

        .PARAMETER Collection
            The collection to add empty privilege rights to. If not provided or null, a new
            System.Collections.Generic.List[object] collection will be created.

        .EXAMPLE
            $rightsCollection = [System.Collections.Generic.List[object]]::new()
            Add-EmptyPrivilegeRightLocal -Collection $rightsCollection

            Creates a new collection and adds empty privilege rights to it.

        .EXAMPLE
            $existingCollection = [System.Collections.Generic.List[object]]::new()
            $item = @{
                Section = 'Privilege Rights'
                Key = 'SeDenyInteractiveLogonRight'
                Members = @('Everyone')
            }
            $existingCollection.Add($item)
            Add-EmptyPrivilegeRightLocal -Collection $existingCollection

            Adds empty privilege rights to an existing collection that already contains other rights.

        .INPUTS
            System.Collections.Generic.List[object]
            You can pipe a collection object to this function.

        .OUTPUTS
            System.Void
            This function does not generate any output.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Get-PrivilegeRightMapping                  ║ EguibarIT.DelegationPS
                Write-Debug                                ║ Microsoft.PowerShell.Utility
                Write-Warning                              ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         2.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS

        .COMPONENT
            Group Policy

        .ROLE
            Security

        .FUNCTIONALITY
            Group Policy Management, Privilege Rights
    #>

    [CmdletBinding()]
    [OutputType([System.Void])]

    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]
        $Collection
    )

    # First ensure we have a valid collection
    if ($null -eq $Collection) {
        Write-Warning -Message 'Collection parameter is null. Creating a new collection.'
        $Collection = [System.Collections.Generic.List[object]]::new()
    }

    Write-Debug -Message ('Function called with collection type: {0}, Count: {1}' -f
        $Collection.GetType().FullName, $Collection.Count)

    $emptyRights = @(
        'SeTrustedCredManAccessPrivilege',
        'SeTcbPrivilege',
        'SeCreateTokenPrivilege',
        'SeCreatePermanentPrivilege',
        'SeDebugPrivilege',
        'SeLockMemoryPrivilege'
    )

    $rightMappings = Get-PrivilegeRightMapping

    foreach ($right in $emptyRights) {
        # Create a strongly typed list for members that always has Count property
        $emptyMembers = [System.Collections.Generic.List[string]]::new()

        # Directly add the right to the collection to avoid parameter binding issues
        $rightHash = @{
            Section     = 'Privilege Rights'
            Key         = $right
            Members     = $emptyMembers  # Empty list that won't trigger binding issues
            Description = $rightMappings[$right]
        }

        try {
            Write-Debug -Message ('Adding empty right {0} directly to collection' -f $right)
            $Collection.Add($rightHash)
            Write-Debug -Message ('Added empty right {0} directly to collection' -f $right)
        } catch {
            Write-Warning -Message ('Failed to add empty right {0}: {1}' -f $right, $_.Exception.Message)
        } #end try-catch
    } #end foreach
} #end function

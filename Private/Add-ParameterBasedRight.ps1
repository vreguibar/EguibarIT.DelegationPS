function Add-ParameterBasedRight {
    <#
        .SYNOPSIS
            Adds privilege rights based on parameters passed to Set-GpoPrivilegeRight.

        .DESCRIPTION
            This internal helper function processes the parameters that were bound to the
            Set-GpoPrivilegeRight cmdlet and adds the appropriate privilege rights to the
            specified collection. It maps parameter names to privilege rights using
            pre-defined mappings and handles the progress reporting during processing.

            The function is designed to work with Group Policy privilege rights configuration
            and provides a structured way to apply multiple privilege settings in a batch operation.

        .PARAMETER Collection
            A System.Collections.Generic.List<object> that will store the privilege rights.
            This collection will be modified by adding new rights based on the bound parameters.

        .PARAMETER BoundParameters
            The $PSBoundParameters dictionary from the calling function (typically Set-GpoPrivilegeRight).
            This contains the parameter names and values that were passed to the calling function.

        .EXAMPLE
            $rightsCollection = [System.Collections.Generic.List[object]]::new()
            Add-ParameterBasedRight -Collection $rightsCollection -BoundParameters $PSBoundParameters

            Processes the bound parameters from the calling function and adds appropriate
            rights to the $rightsCollection.

        .INPUTS
            None. This function does not accept pipeline input.

        .OUTPUTS
            System.Void

            This function does not produce any output. It modifies the collection passed
            through the Collection parameter.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Write-Debug                                ║ Microsoft.PowerShell.Utility
                Write-Warning                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Write-Progress                             ║ Microsoft.PowerShell.Utility
                Get-ParameterToPrivilegeRightMapping       ║ EguibarIT.DelegationPS
                Get-PrivilegeRightMapping                  ║ EguibarIT.DelegationPS
                Add-Right                                  ║ EguibarIT.DelegationPS

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
            Group Policy

        .ROLE
            Security

        .FUNCTIONALITY
            Privilege Rights Management
    #>

    [CmdletBinding()]
    [OutputType([System.Void])]

    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]]
        $Collection,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]
        $BoundParameters
    )

    # Ensure collection is correctly initialized
    if ($null -eq $Collection) {
        $ErrorMessage = 'Collection parameter cannot be null in Add-ParameterBasedRight'
        Write-Error -Message $ErrorMessage
        throw $ErrorMessage
    }

    # Create a new collection if empty
    if ($Collection.Count -eq 0) {
        Write-Debug -Message 'Collection is empty. Continuing with the empty collection.'
    }

    $parameterMappings = Get-ParameterToPrivilegeRightMapping
    $rightMappings = Get-PrivilegeRightMapping

    $totalParameters = ($parameterMappings.Keys | Where-Object { $BoundParameters.ContainsKey($_) }).Count
    $current = 0

    foreach ($paramName in $BoundParameters.Keys) {

        # Skip GpoToModify parameter
        if ($paramName -eq 'GpoToModify') {
            continue
        } #end if

        # Check if parameter is in our mapping
        if ($parameterMappings.ContainsKey($paramName)) {

            $current++
            $percentComplete = ($current / $totalParameters) * 100

            $Splat = @{
                Activity        = 'Processing privilege rights'
                Status          = 'Processing {0}' -f $paramName
                PercentComplete = $percentComplete
            }
            Write-Progress @Splat


            $rightKey = $parameterMappings[$paramName]
            $members = $BoundParameters[$paramName]

            if ($null -ne $members) {

                $addRightParams = @{
                    Key         = $rightKey
                    Members     = $members
                    Description = $rightMappings[$rightKey]
                    Collection  = $Collection
                }

                try {

                    Add-Right @addRightParams

                } catch {

                    Write-Warning -Message ('Failed to add right {0} for parameter {1}: {2}' -f
                        $rightKey, $paramName, $_.Exception.Message)

                } #end try-catch
            } #end if
        } #end if
    } #end foreach
    Write-Progress -Activity 'Processing privilege rights' -Completed -Status 'Completed'
} #end function

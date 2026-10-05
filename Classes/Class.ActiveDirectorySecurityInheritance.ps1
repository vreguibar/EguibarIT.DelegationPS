class ActiveDirectorySecurityInheritance : System.Management.Automation.IValidateSetValuesGenerator {
    [String[]] GetValidValues() {

        <#
        .SYNOPSIS
            Returns the valid values for the ActiveDirectorySecurityInheritance validation set.

        .DESCRIPTION
            This method provides the supported inheritance modes used by the module's
            validation metadata and parameter constraints.

        .OUTPUTS
            System.String[]

        .NOTES
            Version:         2.0
            DateModified:    23/09/2026
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com
        #>

        $ActiveDirectorySecurityInheritance = @(
            'None',
            'All',
            'Descendents',
            'SelfAndChildren',
            'Children'
        )
        return $ActiveDirectorySecurityInheritance
    }
} #end Class

# https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurityinheritance?view=dotnet-plat-ext-8.0

# To get all enums in a namespace we use:
# [enum]::GetNames([System.DirectoryServices.ActiveDirectorySecurityInheritance])

# To use ENUM in Param
# [ValidateSet([ActiveDirectorySecurityInheritance],ErrorMessage="Value '{0}' is invalid. Try one of: {1}")]

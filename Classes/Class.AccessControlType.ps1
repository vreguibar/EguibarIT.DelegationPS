class AccessControlType : System.Management.Automation.IValidateSetValuesGenerator {
    [String[]] GetValidValues() {

        <#
        .SYNOPSIS
            Returns the valid values for the AccessControlType validation set.

        .DESCRIPTION
            This method provides the supported access-control values used by the module's
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

        $AccessControlType = @(
            'Allow',
            'Deny'
        )
        return $AccessControlType
    }
} #end Class

# https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.accesscontroltype?view=net-8.0

# To get all enums in a namespace we use:
# [enum]::GetNames([System.Security.AccessControl.AccessControlType])

# To use ENUM in Param
# [ValidateSet([ActiveDirectorySecurityInheritance],ErrorMessage="Value '{0}' is invalid. Try one of: {1}")]

class AccessControlType : System.Management.Automation.IValidateSetValuesGenerator {
    [String[]] GetValidValues() {

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

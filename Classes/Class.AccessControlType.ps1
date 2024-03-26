class AccessControlType : System.Management.Automation.IValidateSetValuesGenerator {
    [String[]] GetValidValues() {

        $AccessControlType = @(
            'Allow',
            'Deny'
        )
        return $AccessControlType
    }
} #end Class

# To get all enums in a namespace we use:
# [enum]::GetNames([System.Security.AccessControl.AccessControlType])

# To use ENUM in Param
# [ValidateSet([ActiveDirectorySecurityInheritance],ErrorMessage="Value '{0}' is invalid. Try one of: {1}")]

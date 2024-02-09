class AccessControlType : System.Management.Automation.IValidateSetValuesGenerator {
    [String[]] GetValidValues() {

        $AccessControlType = @(
            'Allow',
            'Deny'
        )
        return $AccessControlType
    }
} #end Class
# [ValidateSet([ActiveDirectorySecurityInheritance],ErrorMessage="Value '{0}' is invalid. Try one of: {1}")]

class ActiveDirectorySecurityInheritance : System.Management.Automation.IValidateSetValuesGenerator {
    [String[]] GetValidValues() {

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

# To get all enums in a namespace we use:
# [enum]::GetNames([System.DirectoryServices.ActiveDirectorySecurityInheritance])

# To use ENUM in Param
# [ValidateSet([ActiveDirectorySecurityInheritance],ErrorMessage="Value '{0}' is invalid. Try one of: {1}")]

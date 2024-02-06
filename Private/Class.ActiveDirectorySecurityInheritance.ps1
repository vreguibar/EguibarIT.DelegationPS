class ActiveDirectorySecurityInheritance : System.Management.Automation.IValidateSetValuesGenerator {
    [String[]] GetValidValues() {

        $Script:ActiveDirectorySecurityInheritance = @(
            'None',
            'All',
            'Descendents',
            'SelfAndChildren',
            'Children'
        )
        return $Script:ActiveDirectorySecurityInheritance
    }
} #end Class
# [ValidateSet([ActiveDirectorySecurityInheritance],ErrorMessage="Value '{0}' is invalid. Try one of: {1}")]

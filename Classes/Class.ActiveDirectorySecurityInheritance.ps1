﻿class ActiveDirectorySecurityInheritance : System.Management.Automation.IValidateSetValuesGenerator {
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
# [ValidateSet([ActiveDirectorySecurityInheritance],ErrorMessage="Value '{0}' is invalid. Try one of: {1}")]

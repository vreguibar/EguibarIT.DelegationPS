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

# https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurityinheritance?view=dotnet-plat-ext-8.0

# To get all enums in a namespace we use:
# [enum]::GetNames([System.DirectoryServices.ActiveDirectorySecurityInheritance])

# To use ENUM in Param
# [ValidateSet([ActiveDirectorySecurityInheritance],ErrorMessage="Value '{0}' is invalid. Try one of: {1}")]

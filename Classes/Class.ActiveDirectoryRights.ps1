class ActiveDirectoryRights : System.Management.Automation.IValidateSetValuesGenerator {
    [String[]] GetValidValues() {

        $ActiveDirectoryRights = @(
            'AccessSystemSecurity',
            'CreateChild',
            'DeleteChild',
            'Delete',
            'DeleteTree',
            'ExtendedRight',
            'GenericAll',
            'GenericExecute',
            'GenericRead',
            'GenericWrite',
            'ListChildren',
            'ListObject',
            'ReadControl',
            'ReadProperty',
            'Self',
            'Synchronize',
            'WriteDacl',
            'WriteOwner',
            'WriteProperty'
        )
        return $ActiveDirectoryRights
    }
} #end Class
# [ValidateSet([ActiveDirectoryRights],ErrorMessage="Value '{0}' is invalid. Try one of: {1}")]

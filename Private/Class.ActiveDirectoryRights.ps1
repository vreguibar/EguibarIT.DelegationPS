class ActiveDirectoryRights : System.Management.Automation.IValidateSetValuesGenerator {
    [String[]] GetValidValues() {

        $Script:ActiveDirectoryRights = @(
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
        return $Script:ActiveDirectoryRights
    }
} #end Class
# [ValidateSet([ActiveDirectoryRights],ErrorMessage="Value '{0}' is invalid. Try one of: {1}")]

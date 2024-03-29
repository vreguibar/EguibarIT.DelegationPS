﻿class ActiveDirectoryRights : System.Management.Automation.IValidateSetValuesGenerator {
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
# https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=dotnet-plat-ext-8.0

# To get all enums in a namespace we use:
# [enum]::GetNames([System.DirectoryServices.ActiveDirectoryRights])

# To use ENUM in Param
# [ValidateSet([ActiveDirectoryRights],ErrorMessage="Value '{0}' is invalid. Try one of: {1}")]

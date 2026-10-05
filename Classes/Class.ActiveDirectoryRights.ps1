class ActiveDirectoryRights : System.Management.Automation.IValidateSetValuesGenerator {
    [String[]] GetValidValues() {

        <#
        .SYNOPSIS
            Returns the valid values for the ActiveDirectoryRights validation set.

        .DESCRIPTION
            This method provides the supported Active Directory rights values used by the
            module's access-control validation metadata and parameter constraints.

        .OUTPUTS
            System.String[]

        .NOTES
            Version:         2.0
            DateModified:    23/09/2026
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com
        #>

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

Function Set-GpoRestrictedGroup {
    <#
        .Synopsis

        .DESCRIPTION

        .EXAMPLE

        .EXAMPLE

        .PARAMETER GpoToModify
            Name of the GPO which will get the Restricted Groups modification.
        .PARAMETER MergeUsers
            Switch indicator to merge users (retain existing users). Default is not present, meaning all users in group will be removed
        .PARAMETER LocalAdminUsers
            Identity (SamAccountName) to be included in the Local Administrators group.
        .PARAMETER LocalBackupOpUsers
            Identity (SamAccountName) to be included in the Local Backup Operator group.
        .PARAMETER LocalEventLogReaders
            Identity (SamAccountName) to be included in the Local Event Log Readers group.
        .PARAMETER LocalPerfLogUsers
            Identity (SamAccountName) to be included in the Local Performance Log Users group.
        .PARAMETER LocalPerfMonitorUsers
            Identity (SamAccountName) to be included in the Local Performance Monitor Users group.
        .PARAMETER LocalRemoteDesktopUsers
            Identity (SamAccountName) to be included in the Local Remote Desktop Users group.
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
        .NOTES
            Version:         1.2
            DateModified:    07/Dec/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
}

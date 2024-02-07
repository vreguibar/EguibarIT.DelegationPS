Function New-ExtenderRightHashTable {
    <#
        .Synopsis
            Function to Read all Extended Rights GUID from Schema
        .DESCRIPTION
            Function that reads all Extended Rights GUID from the Schema and stores into
            a Hash Table named $extendedrightsmap
        .EXAMPLE
            New-ExtenderRightHashTable
        .NOTES
            Version:         1.0
            DateModified:    19/Feb/2015
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Low')]
    [OutputType([System.Collections.Hashtable])]

    Param()

    Begin {
        ##############################
        # Variables Definition
        $TmpMap = @{}

    } #end Begin

    Process {
        try {
            If ( ($null -eq $Variables.ExtendedRightsMap) -and
                 ($Variables.ExtendedRightsMap -ne 0) -and
                 ($Variables.ExtendedRightsMap -ne '') -and
                 (   ($Variables.ExtendedRightsMap -isnot [array]) -or
                     ($Variables.ExtendedRightsMap.Length -ne 0)) -and
                 ($Variables.ExtendedRightsMap -ne $false)
            ) {

                # store the GUID value of each extended right in the forest
                $Splat = @{
                    SearchBase = $Variables.configurationNamingContext
                    LDAPFilter = '(&(objectclass=controlAccessRight)(rightsguid=*))'
                    Properties = 'DisplayName', 'rightsGuid'
                }
                $AllExtended = Get-ADObject @Splat
                ForEach ($Item in $AllExtended) {
                    $TmpMap.Add($Item.displayName, [system.guid]$Item.rightsGuid)
                }
                # Include "ALL [nullGUID]"
                $TmpMap.Add('All', [System.GUID]'00000000-0000-0000-0000-000000000000')
            } #end If
        } catch {
            throw 
        }

        $Variables.ExtendedRightsMap = $TmpMap
    } #end Process

    End {
    } #end END
}

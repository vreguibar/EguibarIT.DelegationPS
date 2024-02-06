Function Get-AttributeSchemaHashTable {
    <#
        .Synopsis
            Function to Read all GUID from Schema
        .DESCRIPTION
            Function that reads all GUID from the Schema and stores into a Hashtable named $guidmap
        .EXAMPLE
            New-GuidObjectHashTable
        .EXAMPLE
            $guidmap = New-GuidObjectHashTable
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
            If ( ($null -eq $Variables.GuidMap) -and
                 ($Variables.GuidMap -ne 0) -and
                 ($Variables.GuidMap -ne '') -and
                 (   ($Variables.GuidMap -isnot [array]) -or
                     ($Variables.GuidMap.Length -ne 0)) -and
                 ($Variables.GuidMap -ne $false)
            ) {

                #store the GUID value of each schema class and attribute
                $Splat = @{
                    SearchBase = $Variables.SchemaNamingContext.ToString()
                    LDAPFilter = '(schemaidguid=*)'
                    Properties = 'lDAPDisplayName', 'schemaIDGUID'
                }
                $AllSchema = Get-ADObject @Splat
                Foreach ($item in $AllSchema) {
                    $TmpMap.Add($item.lDAPDisplayName, [System.GUID]$item.schemaIDGUID)
                }
                # Include "ALL [nullGUID]"
                $TmpMap.Add('All', [System.GUID]'00000000-0000-0000-0000-000000000000')
            } #end If
        }
        catch {
            throw 
        }

        $Variables.GuidMap = $TmpMap
    } #end Process

    End {
    } # end END
}

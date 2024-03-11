Function Get-AttributeSchemaHashTable {
    <#
        .Synopsis
            Function to Read all GUID from Schema
        .DESCRIPTION
            Function that reads all GUID from the Schema and stores into a Hashtable named $guidmap
        .EXAMPLE
            Get-AttributeSchemaHashTable
        .EXAMPLE
            $guidmap = Get-AttributeSchemaHashTable
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-ADObject                           | ActiveDirectory
                Write-Progress                         | PSWriteLog
                Get-CurrentErrorToDisplay              | EguibarIT.DelegationPS
        .NOTES
            Version:         1.1
            DateModified:    11/Mar/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([System.Collections.Hashtable])]

    Param()

    Begin {
        $error.clear()

        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('This function does not uses any Parameter' )

        ##############################
        # Variables Definition

        [hashtable]$TmpMap = [hashtable]::New()
        [hashtable]$Splat = [hashtable]::New()
        [int32]$i = 0

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
                    SearchBase = $Variables.SchemaNamingContext
                    LDAPFilter = '(schemaidguid=*)'
                    Properties = 'lDAPDisplayName', 'schemaIDGUID'
                }
                $AllSchema = Get-ADObject @Splat

                Foreach ($item in $AllSchema) {
                    $i ++

                    $parameters = @{
                        Activity         = 'Adding {0} Schema attributes to Hashtable' -f $AllSchema.count
                        Status           = 'Reading attribute number {0}  ' -f $i
                        PercentComplete  = ($i / $AllSchema.count) * 100
                        CurrentOperation = '      Processing Attribute...: {0}' -f $item.lDAPDisplayName
                    }
                    Write-Progress @parameters


                    $TmpMap.Add($item.lDAPDisplayName, [System.GUID]$item.schemaIDGUID)
                }
                # Include "ALL [nullGUID]"
                $TmpMap.Add('All', [System.GUID]'00000000-0000-0000-0000-000000000000')
            } #end If
        } catch {
            Get-CurrentErrorToDisplay -CurrentError $error[0]
        } #end Try-Catch

    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''

        # Only fill $Variables.GuidMap in case is not empty
        If (-not $TmpMap) {
            $Variables.GuidMap = $TmpMap
        }

        Return $Variables.GuidMap
    } # end END
}

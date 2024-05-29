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
        Write-Verbose -Message 'This function does not uses any Parameter.'

        ##############################
        # Variables Definition

        [hashtable]$TmpMap = [hashtable]::New()
        [hashtable]$Splat = [hashtable]::New()
        [int32]$i = 0

    } #end Begin

    Process {
        try {

            If ( (-not $Variables.GuidMap) -or
                ($Variables.GuidMap.Count -eq 0) -or
                ($Variables.GuidMap -eq 0) -or
                ($Variables.GuidMap -eq '') -or
                ($Variables.GuidMap -eq $false)
            ) {

                Write-Verbose -Message 'The GUID map is null, empty, zero, or false.'
                Write-Verbose -Message 'Getting the GUID value of each schema class and attribute'
                #store the GUID value of each schema class and attribute
                $Splat = @{
                    SearchBase = $Variables.SchemaNamingContext
                    LDAPFilter = '(schemaidguid=*)'
                    Properties = 'lDAPDisplayName', 'schemaIDGUID'
                }
                $AllSchema = Get-ADObject @Splat

                Write-Verbose -Message 'Processing all schema class and attribute'
                Foreach ($item in $AllSchema) {
                    $i ++

                    $Splat = @{
                        Activity         = 'Adding {0} Schema attributes to Hashtable' -f $AllSchema.count
                        Status           = 'Reading attribute number {0}  ' -f $i
                        PercentComplete  = ($i / $AllSchema.count) * 100
                        CurrentOperation = '      Processing Attribute...: {0}' -f $item.lDAPDisplayName
                    }
                    Write-Progress @Splat


                    $TmpMap.Add($item.lDAPDisplayName, [System.GUID]$item.schemaIDGUID)
                } #end ForEach

                # Include "ALL [nullGUID]"
                $TmpMap.Add('All', $Constants.guidNull)

                Write-Verbose -Message '$Variables.GuidMap was empty. Adding values to it!'
                $Variables.GuidMap = $TmpMap

            } #end If
        } catch {
            Get-CurrentErrorToDisplay -CurrentError $error[0]
        } #end Try-Catch

    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) fill up GuidMap variable."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } # end END
}

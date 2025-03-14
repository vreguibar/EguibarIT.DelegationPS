﻿Function Get-AttributeSchemaHashTable {
    <#
        .Synopsis
            Function to Read all GUID from Schema
        .DESCRIPTION
            Function that reads all GUID from the Schema and stores into a Hashtable named $Variables.GuidMap
        .EXAMPLE
            Get-AttributeSchemaHashTable
        .EXAMPLE
            Get-AttributeSchemaHashTable
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

        Set-StrictMode -Version Latest

        $txt = ($Variables.HeaderDelegation -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            'This function does not uses any Parameter.'
        )
        Write-Verbose -Message $txt

        ##############################
        # Variables Definition

        [hashtable]$TmpMap = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [int32]$i = 0
        [bool]$FillUp = $false

    } #end Begin

    Process {

        # Check if $Variables.GuidMap is Null or Empty
        If ( [string]::IsNullOrEmpty($Variables.GuidMap) ) {
            # We have to fill it up
            $FillUp = $true
        }

        If ($Force) {
            # We are FORCED to fill it up
            $FillUp = $true
        }

        try {

            If ( $FillUp ) {

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
                        PercentComplete  = [math]::Round(($i / $AllSchema.Count) * 100, 2)
                        CurrentOperation = '      Processing Attribute...: {0}' -f $item.lDAPDisplayName
                    }
                    Write-Progress @Splat

                    # add current Guid to $TempMap
                    $TmpMap.Add($item.lDAPDisplayName, ([System.GUID]$item.schemaIDGUID).GUID)
                } #end ForEach

                # Include "ALL [nullGUID]"
                $TmpMap.Add('All', $Constants.guidNull)

                Write-Verbose -Message '$Variables.GuidMap was empty. Adding values to it!'
                $Variables.GuidMap = $TmpMap

            } #end If
        } catch {
            Write-Error -Message 'Error when filling GUIDmap variable'
            throw
        } Finally {
            # Remove completed progress bar
            $Splat = @{
                Activity         = 'Adding Schema attributes to Hashtable'
                Status           = 'Completed'
                CurrentOperation = 'Finished'
                PercentComplete  = 100
                Completed        = $true
            }
            Write-Progress @Splat
        } #end Try-Catch-Finally

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'filling up GuidMap variable.'
        )
        Write-Verbose -Message $txt
    } # end END
}

Function Get-ExtendedRightHashTable {
    <#
        .Synopsis
            Function to Read all Extended Rights GUID from Schema
        .DESCRIPTION
            Function that reads all Extended Rights GUID from the Schema and stores into
            a Hash Table named $extendedrightsmap
        .EXAMPLE
            Get-ExtendedRightHashTable
        .NOTES
            Version:         1.0
            DateModified:    19/Feb/2015
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

            If ( ($null -eq $Variables.ExtendedRightsMap) -and
                 ($Variables.ExtendedRightsMap -ne 0) -and
                 ($Variables.ExtendedRightsMap -ne '') -and
                 (   ($Variables.ExtendedRightsMap -isnot [array]) -or
                     ($Variables.ExtendedRightsMap.Length -ne 0)) -and
                 ($Variables.ExtendedRightsMap -ne $false)
            ) {

                Write-Verbose -Message 'Getting the GUID value of each Extended attribute'
                # store the GUID value of each extended right in the forest
                $Splat = @{
                    SearchBase = ('CN=Extended-Rights,{0}' -f $Variables.configurationNamingContext)
                    LDAPFilter = '(objectclass=controlAccessRight)'
                    Properties = 'DisplayName', 'rightsGuid'
                }
                $AllExtended = Get-ADObject @Splat

                Write-Verbose -Message 'Processing all Extended attributes'
                ForEach ($Item in $AllExtended) {
                    $i ++

                    $Splat = @{
                        Activity         = 'Adding {0} Extended attributes to Hashtable' -f $AllExtended.count
                        Status           = 'Reading extended attribute number {0}  ' -f $i
                        PercentComplete  = ($i / $AllExtended.count) * 100
                        CurrentOperation = '      Processing Extended Attribute...: {0}' -f $item.lDAPDisplayName
                    }
                    Write-Progress @Splat

                    $TmpMap.Add($Item.displayName, [system.guid]$Item.rightsGuid)
                }
                # Include "ALL [nullGUID]"
                $TmpMap.Add('All', [System.GUID]'00000000-0000-0000-0000-000000000000')

                Write-Verbose -Message '$Variables.GuidMap was empty. Adding values to it!'
                $Variables.ExtendedRightsMap = $TmpMap

            } #end If
        } catch {
            Get-CurrentErrorToDisplay -CurrentError $error[0]
        } #end Try-Catch

    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) fill up ExtendedRightsMap variable."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}

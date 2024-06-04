Function Get-ExtendedRightHashTable {
    <#
        .Synopsis
            Function to Read all Extended Rights GUID from Schema
        .DESCRIPTION
            Function that reads all Extended Rights GUID from the Schema and stores into
            a Hash Table named $Variables.ExtendedRightsMap
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

        [hashtable]$TmpMap = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [int32]$i = 0

    } #end Begin

    Process {
        try {

            If ( (-not $Variables.ExtendedRightsMap) -or
                ($Variables.ExtendedRightsMap.Count -eq 0) -or
                ($Variables.ExtendedRightsMap -eq 0) -or
                ([string]::IsNullOrEmpty($Variables.ExtendedRightsMap)) -or
                ($Variables.ExtendedRightsMap -eq $false)
            ) {

                Write-Verbose -Message 'The Extended Rights map is null, empty, zero, or false.'
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
                        PercentComplete  = [math]::Round(($i / $AllExtended.Count) * 100, 2)
                        CurrentOperation = '      Processing Extended Attribute...: {0}' -f $item.lDAPDisplayName
                    }
                    Write-Progress @Splat

                    # add current Guid to $TempMap
                    $TmpMap.Add($Item.displayName, [system.guid]$Item.rightsGuid)
                } #end Foreach

                # Include "ALL [nullGUID]"
                $TmpMap.Add('All', $Constants.guidNull)

                Write-Verbose -Message '$Variables.ExtendedRightsMap was empty. Adding values to it!'
                $Variables.ExtendedRightsMap = $TmpMap

            } else {
                Write-Verbose -Message '$Variables.ExtendedRightsMap id defined. You can use it!'
            } #end If-Else
        } catch {
            ## Get-CurrentErrorToDisplay -CurrentError $error[0]
            throw
        } Finally {
            # Remove completed progress bar
            $Splat = @{
                Activity         = 'Adding Extended attributes to Hashtable'
                Status           = 'Completed'
                CurrentOperation = 'Finished'
                PercentComplete  = 100
                Completed        = $true
            }
            Write-Progress @Splat
        } #end Try-Catch-Finally

    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) fill up ExtendedRightsMap variable."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end END
}

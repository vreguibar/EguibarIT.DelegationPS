Function Get-ExtendedRightHashTable {
    <#
        .SYNOPSIS
            Gets all Extended Rights GUIDs from Active Directory and stores them in a hashtable.

        .DESCRIPTION
            This function queries the Active Directory Configuration partition and retrieves all Extended Rights GUIDs,
            creating a hashtable that maps display names to their corresponding GUIDs.
            The hashtable is stored in the $Variables.ExtendedRightsMap variable for later use.

            This function is essential for performing extended rights operations in Active Directory,
            particularly for security descriptors and permission management.

        .PARAMETER Force
            Forces the function to rebuild the Extended Rights map even if it already exists.

        .PARAMETER Server
            Specifies the domain controller to use for the query.
            If not provided, the function will use the default domain controller.

        .EXAMPLE
            Get-ExtendedRightHashTable

            Retrieves all Extended Rights GUIDs and stores them in $Variables.ExtendedRightsMap.

        .EXAMPLE
            Get-ExtendedRightHashTable -Force

            Forces the function to rebuild the Extended Rights map even if it already exists.

        .EXAMPLE
            Get-ExtendedRightHashTable -Server 'DC01.EguibarIT.local'

            Retrieves all Extended Rights GUIDs from the specified domain controller.

        .OUTPUTS
            System.Collections.Hashtable

            A hashtable mapping DisplayName of extended rights to their corresponding GUIDs.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Get-ADObject                               ║ ActiveDirectory
                Write-Progress                             ║ Microsoft.PowerShell.Utility
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Write-Debug                                ║ Microsoft.PowerShell.Utility
                Write-Warning                              ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.1
            DateModified:    21/Mar/2025
            LastModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Public/Get-ExtendedRightHashTable.ps1
    #>

    [CmdletBinding(
        SupportsShouldProcess = $false,
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.Collections.Hashtable])]

    Param(
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            Position = 0,
            HelpMessage = 'Forces the function to rebuild the Extended Rights map even if it already exists.'
        )]
        [Alias('Rebuild')]
        [switch]$Force,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            Position = 1,
            HelpMessage = 'Specifies the domain controller to use for the query.'
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('DC', 'DomainController')]
        [string]$Server
    )

    Begin {

        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and $null -ne $Variables.HeaderDelegation) {
            $txt = ($Variables.HeaderDelegation -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end if


        ##############################
        # Variables Definition

        [hashtable]$TmpMap = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [int32]$i = 0
        [bool]$FillUp = $false

        [hashtable]$ProgressSplat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [int32]$ProcessedItems = 0
        [bool]$NeedToFillExtendedRightsMap = $false
        [int32]$BatchSize = 1000 # Optimized batch size for AD queries


        $Splat = @{
            SearchBase = ('CN=Extended-Rights,{0}' -f $Variables.configurationNamingContext)
            LDAPFilter = '(objectclass=controlAccessRight)'
            Properties = 'DisplayName', 'rightsGuid'
        }

        # Add server if specified
        if ($PSBoundParameters.ContainsKey('Server')) {

            $ADSplat.Add('Server', $Server)
            Write-Debug -Message ('Using specified server: {0}' -f $Server)

        } #end If

    } #end Begin

    Process {

        # Check if $Variables.ExtendedRightsMap is Null or Empty
        If ($Force -or
            [string]::IsNullOrEmpty($Variables.ExtendedRightsMap) -or
            $Variables.ExtendedRightsMap.Count -eq 0) {

            # We have to fill it up
            $FillUp = $true
            Write-Debug -Message 'The Extended Rights map is null, empty, or Force parameter was specified.'

        } else {

            Write-Debug -Message 'Extended Rights map already exists. Use -Force to rebuild it.'

        } #end If-Else

        If ( $FillUp ) {
            try {
                Write-Debug -Message 'Getting the GUID value of each Extended Right'

                # Add pagination parameters for large environments
                $ADSplat.Add('ResultPageSize', $BatchSize)

                # Execute the AD query with optimized filter
                Write-Debug -Message ('Executing AD query with parameters: {0}' -f ($ADSplat | ConvertTo-Json -Compress))
                $AllExtended = Get-ADObject @Splat

                $ExtendedRightsCount = ($AllExtended | Measure-Object).Count
                Write-Debug -Message ('Found {0} Extended Rights objects' -f $ExtendedRightsCount)

                # Process Extended Rights objects
                ForEach ($Item in $AllExtended) {
                    $ProcessedItems++

                    # Update progress bar
                    $ProgressSplat = @{
                        Activity         = 'Adding Extended Rights to Hashtable'
                        Status           = ('Processing: {0}/{1} ({2:P2} complete)' -f $ProcessedItems, $ExtendedRightsCount, ($ProcessedItems / $ExtendedRightsCount))
                        PercentComplete  = [math]::Round(($ProcessedItems / $ExtendedRightsCount) * 100, 2)
                        CurrentOperation = ('Processing Extended Right: {0}' -f $Item.DisplayName)
                    }
                    Write-Progress @ProgressSplat

                    # Convert rightsGuid to string GUID format and add to hashtable
                    try {

                        $GuidValue = ([System.GUID]$ExtendedItem.rightsGuid).GUID

                        # Check if the DisplayName already exists in the hashtable
                        if (-not $TmpMap.ContainsKey($ExtendedItem.DisplayName)) {

                            $TmpMap.Add($Item.DisplayName, $GuidValue)
                            Write-Debug -Message ('Added {0}: {1}' -f $Item.DisplayName, $GuidValue)

                        } else {

                            Write-Warning -Message ('
                                Duplicate DisplayName found: {0}.
                                Using first occurrence only.' -f $Item.DisplayName
                            )
                        } #end If-Else

                    } catch {

                        Write-Warning -Message ('
                            Error processing Extended Right {0}: {1}' -f $Item.DisplayName, $_.Exception.Message
                        )

                    } #end Try-Catch

                } #end Foreach

                # Add the "All" entry with null GUID
                if (-not [string]::IsNullOrEmpty($Constants.guidNull)) {

                    $TmpMap.Add('All', $Constants.guidNull)
                    Write-Debug -Message ('Added All: {0}' -f $Constants.guidNull)

                } else {

                    # Add a null GUID if $Constants.guidNull is not defined
                    $TmpMap.Add('All', '00000000-0000-0000-0000-000000000000')
                    Write-Debug -Message 'Added All: 00000000-0000-0000-0000-000000000000'

                } #end If-Else

                # Update the module-level variable with our new hashtable
                Write-Verbose -Message 'Updating $Variables.ExtendedRightsMap with new values'
                $Variables.ExtendedRightsMap = $TmpMap

            } catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException] {

                Write-Error -Message ('Active Directory operation error: {0}' -f $_.Exception.Message)
                throw

            } catch [System.UnauthorizedAccessException] {

                Write-Error -Message ('Access denied error: {0}' -f $_.Exception.Message)
                throw

            } catch {

                Write-Error -Message ('Error filling Extended Rights map: {0}' -f $_.Exception.Message)
                throw

            } Finally {

                # Complete the progress bar
                $ProgressSplat = @{
                    Activity         = 'Adding Extended Rights to Hashtable'
                    Status           = 'Completed'
                    CurrentOperation = 'Finished'
                    PercentComplete  = 100
                    Completed        = $true
                }
                Write-Progress @ProgressSplat

            } #end Try-Catch-Finally
        } #end If

    } #end Process

    End {

        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'filling up ExtendedRightsMap variable.'
            )
            Write-Verbose -Message $txt
        } #end if

    } #end END
} #end Function Get-ExtendedRightHashTable

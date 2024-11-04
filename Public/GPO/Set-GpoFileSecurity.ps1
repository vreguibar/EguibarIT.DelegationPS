Function Set-GpoFileSecurity {



    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'medium')]
    [OutputType([void])]

    Param (

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Name of the GPO which will get the Privilege Right modification.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $GpoToModify

    )

    Begin {
        $txt = ($Variables.HeaderDelegation -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)


        # Get the GptTmpl.inf content and store it in variable
        $GptTmpl = Get-GptTemplate -GpoName $PSBoundParameters['GpoToModify']

        if (($null -eq $GptTmpl) -or ($GptTmpl -isnot [IniFileHandler.IniFile])) {
            throw 'Failed to get a valid IniFileHandler.IniFile object from Get-GptTemplate'
        } #end If

        # Check GPT does contains default sections ([Unicode] and [Version])
        If ( -not (($GptTmpl.SectionExists('Version')) -and
            ($GptTmpl.SectionExists('Unicode')))) {

            # Add the missing sections
            $GptTmpl.AddSection('Version')
            $GptTmpl.AddSection('Unicode')

            # Add missing Key-Value pairs
            $GptTmpl.SetKeyValue('Unicode', 'Unicode', 'yes')
            $GptTmpl.SetKeyValue('Version', 'Revision', '1')
            $GptTmpl.SetKeyValue('Version', 'signature', '$CHICAGO$')
        } #end If

    } #end Begin

    Process {



        Foreach ($Rights in $ArrayList) {

            If ($Force -or $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], ('Delegate the permissions for "{0}"?') -f $Rights)) {

                # Check if [[File Security]] section exist. Create it if it does not exist
                If (-not $GptTmpl.SectionExists('File Security')) {

                    Write-Verbose -Message ('Section "[File Security]" does not exist. Creating it!.')
                    $GptTmpl.AddSection('File Security')

                } #end If



                # Add corresponding Key-Value pairs.
                # Each pair will verify proper members are added.
                Try {

                    $Splat = @{
                        CurrentSection = 'File Security'
                        CurrentKey     = $Rights.Key
                        Members        = $Rights.members
                        GptTmpl        = $GptTmpl
                        Confirm        = $false
                    }
                    $GptTmpl = Set-GPOConfigSection @Splat

                } Catch {
                    Write-Error -Message ('Something went wrong. {0}' -f $_)
                    ##Get-ErrorDetail -ErrorRecord $_
                } #end Try-Catch

            } #end If
        } #end Foreach


        # Save INI file
        Try {
            $GptTmpl.SaveFile()
            Write-Verbose -Message ('Saving changes to GptTmpl.inf file og GPO {0}' -f $PSBoundParameters['GpoToModify'])

        } Catch {
            Write-Error -Message ('Something went wrong while trying to save the GptTmpl.inf file...')
            ##Get-ErrorDetail -ErrorRecord $_
            Throw
        }

        # Increment Version
        # Get path to the GPTs.ini file. Increment to make changes.
        Write-Verbose -Message ('Updating GPO version for {0}' -f $PSBoundParameters['GpoToModify'])
        Update-GpoVersion -GpoName $PSBoundParameters['GpoToModify']

    } #end Process

    End {

    } #end
} #end Function

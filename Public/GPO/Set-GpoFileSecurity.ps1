Function Set-GpoFileSecurity {

    <#
        .SYNOPSIS
            Modifies file security settings for specified paths in a GPO.

        .DESCRIPTION
            This function adjusts the file security settings within a specified Group Policy Object (GPO).
            It modifies the permissions based on predefined paths and uses a Security Descriptor Definition Language (SDDL)
            format to define access control entries. The function also ensures that required GptTmpl sections exist,
            and updates the GPO version to reflect changes.

        .PARAMETER GpoToModify
            The name of the Group Policy Object (GPO) to be modified.

        .PARAMETER Group
            The group name or security identifier (SID) that will be delegated specific permissions.

        .EXAMPLE
            Set-GpoFileSecurity -GpoToModify "Default Domain Policy" -Group "Domain Admins" -Verbose

            This command modifies the file security for paths defined in the Default Domain Policy GPO,
            granting permissions to the Domain Admins group and outputs detailed processing information.

        .INPUTS
            None. Parameters are provided by the caller.

        .OUTPUTS
            None.

        .NOTES
            Version:         1.1
            DateModified:    12/Nov/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com

        .NOTES
            Used Functions:
            Name                         | Module
                -------------------------|--------------------------
                Get-FunctionDisplay      | EguibarIT & EguibarIT.DelegationPS
                Get-AdObjectType         | EguibarIT & EguibarIT.DelegationPS
                Get-GptTemplate          | EguibarIT & EguibarIT.DelegationPS
                Update-GpoVersion        | EguibarIT & EguibarIT.DelegationPS
                Write-Error              | Microsoft.PowerShell.Utility
                Write-Verbose            | Microsoft.PowerShell.Utility
    #>

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
        $GpoToModify,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Group Name which will get the delegation',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('IdentityReference', 'Identity', 'Trustee', 'GroupID')]
        $Group,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = 'Force the permission modification without confirmation',
            Position = 2)]
        [Switch]
        $Force

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

        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']
        if (-not $CurrentGroup) {
            throw "Group not found or invalid: $Group"
        } #end If


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

        If (
            $Force -or
            $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], ('Delegate file permissions for "{0}"?') -f $Rights)
        ) {

            # Check if [[File Security]] section exist. Create it if it does not exist
            If (-not $GptTmpl.SectionExists('File Security')) {

                Write-Verbose -Message ('Section "[File Security]" does not exist. Creating it!.')
                $GptTmpl.AddSection('File Security')

            } #end If

            # Define Path
            $AllPaths = @(
                '%AllUsersProfile%',
                '%ProgramFiles%',
                '%ProgramFiles% (x86)',
                '%SystemDrive%\',
                '%SystemDrive%\$Recycle.Bin',
                '%SystemDrive%\Users',
                '%SystemRoot%',
                '%SystemRoot%\Fonts',
                '%SystemRoot%\Globalization',
                '%SystemRoot%\INF',
                '%SystemRoot%\Installer',
                '%SystemRoot%\security',
                '%SystemRoot%\System',
                '%SystemRoot%\System32',
                '%SystemRoot%\SystemResources',
                '%SystemRoot%\SysWOW64',
                '%SystemRoot%\WinSxS'
            )
            # Dynamically add Drive letters
            $AllPaths += (Get-PSDrive -PSProvider FileSystem).Root

            # Define SDDL permissions
            [string]$SDDL = 'D:PAR'
            [string]$SDDL += '(A;OICI;0x1200a9;;;S-1-15-2-1)'
            [string]$SDDL += '(A;OICIIO; FA;;;CO)'
            [string]$SDDL += '(A;OICI; FA;;;SY)'
            [string]$SDDL += '(A;OICI; FA;;;BA)'
            [string]$SDDL += '(A;OICI; 0x1200a9;;;BU)'
            [string]$SDDL += ('(A;OICI; FA;;;{0})' -f $CurrentGroup.SID.Value)


            # Add corresponding values.
            Try {
                # Iterate all paths
                Foreach ($Currentpath in $AllPaths) {

                    #Build single-line string
                    [string]$TmpString = '"{0}",0,"{1}"' -f $Currentpath, $SDDL

                    # Add string to section in template
                    $GptTmpl.AddSimpleString('File Security', $TmpString)
                } #end Foreach

            } Catch {
                Write-Error -Message ('Something went wrong while setting File Security. {0}' -f $_)
                ##Get-ErrorDetail -ErrorRecord $_
            } #end Try-Catch

        } #end If


        # Save INI file
        Try {
            $GptTmpl.SaveFile()
            Write-Verbose -Message ('Saving changes to GptTmpl.inf file og GPO {0}' -f $PSBoundParameters['GpoToModify'])

        } Catch {
            Write-Error -Message ('Something went wrong while trying to save the GptTmpl.inf file...')
            ##Get-ErrorDetail -ErrorRecord $_
            Throw
        } Finally {
            $GptTmpl.Dispose()
        } #end Try-Catch-Finally

        # Increment Version
        # Get path to the GPTs.ini file. Increment to make changes.
        Write-Verbose -Message ('Updating GPO version for {0}' -f $PSBoundParameters['GpoToModify'])
        Update-GpoVersion -GpoName $PSBoundParameters['GpoToModify']

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'configuration of GptTmpl File Security section.'
        )
        Write-Verbose -Message $txt
    } #end
} #end Function

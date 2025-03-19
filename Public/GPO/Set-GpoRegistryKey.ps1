Function Set-GpoRegistryKey {

    <#
        .SYNOPSIS
            Modifies registry key security settings for specified paths within a GPO.

        .DESCRIPTION
            This function allows the modification of registry permissions within a specified Group Policy Object (GPO).
            It applies permissions for a given group or security identifier (SID) to multiple registry paths, setting custom security descriptors.
            The function will attempt to create or modify the "Registry Keys" section in the GptTmpl.inf file associated with the GPO,
            and save these settings back to the GPO for enforcement.

        .PARAMETER GpoToModify
            The name of the GPO to be modified. This parameter is required.

        .PARAMETER Group
            The group name or SID that will receive the specified permissions within the GPO. This parameter is required.

        .PARAMETER Force
            A switch to bypass confirmation and enforce changes directly. When not specified, the function will prompt for confirmation.

        .EXAMPLE
            Set-GpoRegistryKey -GpoToModify "SampleGPO" -Group "Domain Users" -Force

            This command modifies the registry permissions for the "Domain Users" group within the "SampleGPO" GPO,
            setting specific registry paths and permissions as defined within the function.

        .NOTES
            Version:         1.1
            DateModified:    12/Nov/2024
            LastModifiedBy:  Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com

        .NOTES
            Used Functions:
            Name                         | Module
            -----------------------------|--------------------------
            Get-FunctionDisplay          | EguibarIT & EguibarIT.DelegationPS
            Get-AdObjectType             | EguibarIT & EguibarIT.DelegationPS
            Get-GptTemplate              | EguibarIT & EguibarIT.DelegationPS
            Update-GpoVersion            | EguibarIT & EguibarIT.DelegationPS
            Write-Error                  | Microsoft.PowerShell.Utility
            Write-Verbose                | Microsoft.PowerShell.Utility
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
            $PSCmdlet.ShouldProcess($PSBoundParameters['Group'], ('Delegate registry permissions for "{0}"?') -f $Rights)
        ) {

            # Check if [[File Security]] section exist. Create it if it does not exist
            If (-not $GptTmpl.SectionExists('Registry Keys')) {

                Write-Verbose -Message ('Section "[Registry Keys]" does not exist. Creating it!.')
                $GptTmpl.AddSection('Registry Keys')

            } #end If

            # Define Path
            $AllPaths = @(
                'CLASSES_ROOT',
                'MACHINE',
                'MACHINE\BCD00000000',
                'MACHINE\HARDWARE',
                'MACHINE\SAM',
                'MACHINE\SECURITY',
                'MACHINE\SOFTWARE',
                'MACHINE\SOFTWARE\Classes',
                'MACHINE\SOFTWARE\Classes\TypeLib',
                'MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion',
                'MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer',
                'MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData',
                'MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion',
                'MACHINE\SYSTEM',
                'MACHINE\SYSTEM\ControlSet001',
                'MACHINE\SYSTEM\CurrentControlSet',
                'USERS',
                'USERS\.DEFAULT'
            )


            # Define SDDL permissions
            [string]$SDDL = 'D:PAR'
            [string]$SDDL += '(A;CI;KR;;;S-1-15-2-1)'
            [string]$SDDL += '(A;CIIO;KA;;;CO)'
            [string]$SDDL += '(A;CI;KA;;;SY)'
            [string]$SDDL += '(A;CI;KA;;;BA)'
            [string]$SDDL += '(A;CI;KR;;;BU)'
            [string]$SDDL += ('(A;CI;KA;;;{0})' -f $CurrentGroup.SID.Value)


            # Add corresponding values.
            Try {
                # Iterate all paths
                Foreach ($Currentpath in $AllPaths) {

                    #Build single-line string
                    [string]$TmpString = '"{0}",0,"{1}"' -f $Currentpath, $SDDL

                    # Add string to section in template
                    $GptTmpl.AddSimpleString('Registry Keys', $TmpString)
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

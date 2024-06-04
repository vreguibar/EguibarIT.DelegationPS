#
# Module manifest for module 'EguibarIT.DelegationPS'
#
# Generated by: Vicente Rodriguez Eguibar
#
# Generated on: 6/4/2024
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'EguibarIT.DelegationPS.psm1'

# Version number of this module.
ModuleVersion = '1.116.33'

# Supported PSEditions
CompatiblePSEditions = 'Desktop', 'Core'

# ID used to uniquely identify this module
GUID = 'c21c1a04-f27e-44b9-967a-d8f0926c87c5'

# Author of this module
Author = 'Vicente Rodriguez Eguibar'

# Company or vendor of this module
CompanyName = 'EguibarIT'

# Copyright statement for this module
Copyright = 'All rights reserved (c) 2024 - EguibarIT'

# Description of the functionality provided by this module
Description = 'Functions used to implement the Delegation Model with Tiers on the given Active Directory.'

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '7.4'

# Name of the PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# ClrVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
ProcessorArchitecture = 'Amd64'

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'Set-AdAclChangeSite', 'Set-AdAclChangeSiteLink', 
               'Set-AdAclChangeSubnet', 'Set-AdAclCreateDeleteSite', 
               'Set-AdAclCreateDeleteSiteLink', 'Set-AdAclCreateDeleteSubnet', 
               'Set-AdAclFMSOtransfer', 'Set-AdDirectoryReplication', 
               'Set-AdAclBitLockerTPM', 'Set-AdAclChangeComputerPassword', 
               'Set-AdAclComputerAccountRestriction', 
               'Set-AdAclComputerGroupMembership', 'Set-AdAclComputerPersonalInfo', 
               'Set-AdAclComputerPublicInfo', 'Set-AdAclCreateDeleteComputer', 
               'Set-AdAclDnsInfo', 'Set-AdAclEnableDisableComputer', 
               'Set-AdAclMsTsGatewayInfo', 'Set-AdAclRenameComputer', 
               'Set-AdAclResetComputerPassword', 
               'Set-AdAclValidateWriteDnsHostName', 'Set-AdAclValidateWriteSPN', 
               'Set-AdmPwdComputerSelfPermission', 
               'Set-AdmPwdReadPasswordPermission', 
               'Set-AdmPwdResetPasswordPermission', 'Set-DeleteOnlyComputer', 
               'Set-DomainJoinComputer', 'Set-AdAclContactPersonalInfo', 
               'Set-AdAclContactWebInfo', 'Set-AdAclCreateDeleteContact', 
               'Set-AdAclFullControlDFS', 'Set-AdAclCreateDeleteGPO', 
               'Set-AdAclGPoption', 'Set-AdAclLinkGPO', 'Set-AdAclRSoPLogging', 
               'Set-AdAclRSoPPlanning', 'Set-GpoPrivilegeRight', 
               'Set-GpoRestrictedGroup', 'Rename-AdAclGroup', 'Set-AdAclChangeGroup', 
               'Set-AdAclCreateDeleteGroup', 'Set-AdAclUserGroupMembership', 
               'Get-AclAccessRule', 'Get-AclAuditRule', 
               'Get-AttributeSchemaHashTable', 'Get-ExtendedRightHashTable', 
               'Import-MyModule', 'Remove-AccountOperator', 'Remove-AuthUser', 
               'Remove-Everyone', 'Remove-PreWin2000', 'Remove-PreWin2000FromOU', 
               'Remove-PrintOperator', 'Remove-UnknownSID', 
               'Set-AdAclFullControlDHCP', 'Set-AdAclPromoteDC', 'Set-AdInheritance', 
               'Set-CreateDeleteInetOrgPerson', 'Set-AdAclMngPrivilegedAccount', 
               'Set-AdAclMngPrivilegedGroup', 'Rename-AdAclOU', 'Set-AdAclChangeOU', 
               'Set-AdAclCreateDeleteOU', 'Set-AdAclPkiAdmin', 
               'Set-AdAclPkiTemplateAdmin', 'Rename-AdAclPrintQueue', 
               'Set-AdAclChangePrintQueue', 'Set-AdAclCreateDeletePrintQueue', 
               'Set-AdAclCreateDeleteGMSA', 'Set-AdAclCreateDeleteMSA', 
               'Add-GroupToSCManager', 'Add-ServiceAcl', 'Get-SCManagerPermission', 
               'Get-ServiceAcl', 'Remove-GroupFromSCManager', 'Remove-ServiceAcl', 
               'Rename-AdAclUser', 'Set-AdAclChangeUserPassword', 
               'Set-AdAclCreateDeleteUser', 'Set-AdAclEnableDisableUser', 
               'Set-AdAclResetUserPassword', 'Set-AdAclUnlockUser', 
               'Set-AdAclUserAccountRestriction', 'Set-AdAclUserEmailInfo', 
               'Set-AdAclUserGeneralInfo', 'Set-AdAclUserGroupMembership', 
               'Set-AdAclUserLogonInfo', 'Set-AdAclUserPersonalInfo', 
               'Set-AdAclUserPublicInfo', 'Set-AdAclUserWebInfo', 
               'Set-AdAclChangeVolume', 'Set-AdAclCreateDeleteVolume'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
# VariablesToExport = @()

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = 'Windows','ActiveDirectory','ActiveDirectory_Delegation','ActiveDirectory_Security','AD_Security','Security','Delegation','AD_Delegation','DelegationModel','TierModel','RBACmodel','RoleBasedAccessControl_model','DelegationModel','TierModel','RBACmodel','Infrastructure','Testing','Checks','Audits','Checklist','Validation','CredentialTheaf','Pass-the-Hash','Pass-the-Ticket','Golden_Ticket','Silver_Ticket'

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/vreguibar/EguibarIT'

        # A URL to an icon representing this module.
        IconUri = 'https://EguibarIT.com/wp-content/uploads/2017/09/LOGO_FondoBlanco.png'

        # ReleaseNotes of this module
        # ReleaseNotes = ''

        # Prerelease string of this module
        # Prerelease = ''

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        ExternalModuleDependencies = @('ActiveDirectory','GroupPolicy','ServerManager','EguibarIT.DelegationPS')

    } # End of PSData hashtable

 } # End of PrivateData hashtable

# HelpInfo URI of this module
HelpInfoURI = 'https://eguibarit.eu/powershell/delegation-model-powershell-scripts/eguibarit-powershell-module/'

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}


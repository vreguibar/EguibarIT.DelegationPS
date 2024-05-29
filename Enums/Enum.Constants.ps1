﻿$Constants = [ordered] @{

    # Null GUID which is considered as "All"
    #$guidNull  = New-Object -TypeName Guid -ArgumentList 00000000-0000-0000-0000-000000000000
    guidNull = [System.guid]::New('00000000-0000-0000-0000-000000000000')

    # Horizontal Tab
    HTab     = "`t"

    # New NewLine
    NL       = [System.Environment]::NewLine
}

$Splat = @{
    Name        = 'Constants'
    Value       = $Constants
    Description = 'Contains the Constant values used on this module, like GUIDnull, Horizontal Tab or NewLine.'
    Scope       = 'Global'
    Option      = 'Constant'
    Force       = $true
}

# Check if Constants exist. Create it if not
If ( -Not (Test-Path $Constants)) {
    New-Variable @Splat
}

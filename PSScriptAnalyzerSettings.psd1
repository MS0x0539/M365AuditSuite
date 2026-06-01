@{
    ExcludeRules = @(
        # All scripts use Write-Host intentionally for coloured interactive console output.
        # These are admin utilities, not modules or pipeline functions.
        'PSAvoidUsingWriteHost'

        # Empty catch blocks are used intentionally for silent cleanup (e.g. Disconnect-MgGraph,
        # already-assigned idempotency checks). The pattern is deliberate.
        'PSAvoidUsingEmptyCatchBlock'

        # Scripts use plural nouns in function names (Invoke-RoleAssignments, etc.) by design —
        # the noun describes the report/operation, not a single object.
        'PSUseSingularNouns'

        # ShouldProcess (WhatIf/Confirm) is not applicable to standalone scripts.
        'PSUseShouldProcessForStateChangingFunctions'

        # Files are saved as UTF-8 without BOM intentionally (System.IO.File::WriteAllText
        # with UTF8Encoding $false). The BOM rule is aimed at .ps1 module files.
        'PSUseBOMForUnicodeEncodedFile'
    )
}

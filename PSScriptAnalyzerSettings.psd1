@{
    # Tuned rule set for an interactive administrative CLI.
    # Excluded rules are justified noise, not defects:
    #   PSAvoidUsingWriteHost   - this is an interactive tool; Write-Host drives colored
    #                             status output that is the point of the UX.
    #   PSUseShouldProcess...    - the flagged functions are internal, non-exported helpers,
    #                             not public cmdlets; the tool's dry-run is the -Test / -Verify modes.
    #   PSReviewUnusedParameter  - the -Apply/-Undo/-Verify/-Test switches are consumed via
    #                             $PSCmdlet.ParameterSetName, which the analyzer cannot see.
    Severity     = @('Error','Warning')
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'
        'PSUseShouldProcessForStateChangingFunctions'
        'PSReviewUnusedParameter'
    )
}

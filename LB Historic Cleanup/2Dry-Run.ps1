<# 
.SYNOPSIS
Close Microsoft Sentinel incidents in a date window, classify as Undetermined, add a tag, and log to CSV.

.EXAMPLE
.\Close-SentinelIncidents.ps1 -ResourceGroup "<RG>" -Workspace "<Workspace>" `
  -From "2025-03-01T00:00:00Z" -To "2025-04-01T00:00:00Z" `
  -Tag "Historic" -BaseComment "Historic alerts which have been agreed with the local Bacardi team can be closed, due to no additional detections or malicious activity identified. These will be used for correlation and cross checking of any future alerts." -Verbose

# Use -WhatIf to dry-run without making changes.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [Parameter(Mandatory)][string]$ResourceGroup,
  [Parameter(Mandatory)][string]$Workspace,
  [Parameter(Mandatory)][string]$From,
  [Parameter(Mandatory)][string]$To,
  [string]$Classification = "Undetermined",
  [Parameter(Mandatory)][string]$Tag,
  [Parameter(Mandatory)][string]$BaseComment,
  [string]$CsvPath = $(Join-Path -Path (Get-Location) -ChildPath ("sentinel-close-log_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss")))
)

try {
  [datetime]$fromDt = [datetime]::Parse($From)
  [datetime]$toDt   = [datetime]::Parse($To)
} catch {
  throw "From/To must be valid ISO 8601 timestamps (e.g. 2025-03-01T00:00:00Z). Error: $($_.Exception.Message)"
}
if ($toDt -le $fromDt) { throw "Parameter -To must be greater than -From." }

$filter = "properties/createdTimeUtc ge $($fromDt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) and properties/createdTimeUtc lt $($toDt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) and properties/status ne 'Closed'"

Write-Verbose "OData filter: $filter"
$results = @()

$incidents = Get-AzSentinelIncident -ResourceGroupName $ResourceGroup -WorkspaceName $Workspace -Filter $filter

if (-not $incidents) {
  Write-Warning "No incidents matched the filter. Nothing to do."
} else {
  Write-Verbose ("Found {0} incident(s) to process." -f $incidents.Count)
}

foreach ($incident in $incidents) {
  $id                = $incident.Name
  $title             = $incident.Properties.Title
  $statusBefore      = $incident.Properties.Status
  $labelsBefore      = @($incident.Properties.Labels); if (-not $labelsBefore) { $labelsBefore = @() }
  $createdTimeUtc    = $incident.Properties.CreatedTimeUtc
  $incidentName      = $incident.Properties.IncidentName
  $lastModifiedUtc   = $incident.Properties.LastModifiedTimeUtc
  $lastActivityUtc   = $incident.Properties.LastActivityTimeUtc
  $severity          = $incident.Properties.Severity
  
  if ($incident.Properties.Owner) {
    $owner = $incident.Properties.Owner.AssignedTo
} else {
    $owner = $null
}

  $labelsAfter       = ($labelsBefore + $Tag | Select-Object -Unique)

  $tsUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $finalComment = "$BaseComment (Closure timestamp: $tsUtc)"

  $log = [ordered]@{
    TimestampUTC         = $tsUtc
    IncidentId           = $id
    IncidentName         = $incidentName
    Title                = $title
    CreatedTimeUtc       = $createdTimeUtc
    LastModifiedTimeUtc  = $lastModifiedUtc
    LastActivityTimeUtc  = $lastActivityUtc
    Severity             = $severity
    Owner                = $owner
    StatusBefore         = $statusBefore
    StatusAfter          = "Closed"
    Classification       = $Classification
    LabelsBefore         = ($labelsBefore -join ";")
    LabelsAfter          = ($labelsAfter  -join ";")
    CommentSnippet       = ($finalComment.Substring(0, [Math]::Min(120, $finalComment.Length)))
    Result               = "PENDING"
    Error                = $null
  }

  try {
    $target = "Incident '$title' ($id)"
    if ($PSCmdlet.ShouldProcess($target, "Close as $Classification, add tag '$Tag'")) {
      Update-AzSentinelIncident -ResourceGroupName $ResourceGroup -WorkspaceName $Workspace `
        -IncidentId $id `
        -Status "Closed" `
        -Classification $Classification `
        -ClassificationComment $finalComment `
        -Labels $labelsAfter | Out-Null

      $log.Result = "UPDATED"
      Start-Sleep -Milliseconds 200
    } else {
      $log.Result = "WHATIF"
    }
  }
  catch {
    $log.Result = "FAILED"
    $log.Error  = $_.Exception.Message
    Write-Warning "Failed to update $title ($id): $($log.Error)"
  }
  finally {
    $results += New-Object psobject -Property $log
  }
}

$results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
Write-Host "Audit log written to $CsvPath"

$results |
  Select-Object TimestampUTC, IncidentId, IncidentName, Title, CreatedTimeUtc, LastModifiedTimeUtc, LastActivityTimeUtc, Severity, Owner, Result, StatusBefore, StatusAfter, Classification |
  Format-Table -AutoSize

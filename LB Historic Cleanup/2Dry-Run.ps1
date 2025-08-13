<# 
.SYNOPSIS
Close Microsoft Sentinel incidents in a date window, classify as Undetermined, add a tag, and log to CSV.

.EXAMPLE
.\Close-SentinelIncidents.ps1 -ResourceGroup "<RG>" -Workspace "<Workspace>" `
  -From "2025-03-01T00:00:00Z" -To "2025-04-01T00:00:00Z" `
  -Tag "Historic" -BaseComment "Historic alerts which have been agreed with the local Bacardi team can be closed, due to no additional detections or malicious activity identified. These will be used for correlation and cross checking of any future alerts." -Verbose

# Use -WhatIf to dry-run without making changes.
#>

# --- robust, PS5.1-compatible helpers ---
function Get-Prop {
  param($obj, [string[]]$paths)
  foreach ($p in $paths) {
    try {
      $v = $obj | ForEach-Object { Invoke-Expression ('$_.{0}' -f $p) }
      if ($null -ne $v -and "$v" -ne "") { return $v }
    } catch { }
  }
  return $null
}

# Ensure CSV folder exists (so Export-Csv never silently fails)
$csvDir = Split-Path -Path $CsvPath -Parent
if ($csvDir -and -not (Test-Path $csvDir)) {
  New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
}

$ErrorActionPreference = 'Stop'

$filter = "properties/createdTimeUtc ge $($fromDt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) and properties/createdTimeUtc lt $($toDt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) and properties/status ne 'Closed'"
Write-Verbose "OData filter: $filter"

$results   = @()
$incidents = Get-AzSentinelIncident -ResourceGroupName $ResourceGroup -WorkspaceName $Workspace -Filter $filter

if (-not $incidents) {
  Write-Warning "No incidents matched the filter. Nothing to do."
}

foreach ($incident in $incidents) {

  # Try both flattened and nested shapes
  $p = $incident.Properties
  if (-not $p) { $p = $incident }  # fallback if module flattened fields

  $id               = Get-Prop $incident @('Name','Id')
  $title            = Get-Prop $p       @('Title','title')
  $incidentName     = Get-Prop $p       @('IncidentName','incidentName','Name','name')
  $incidentNumber   = Get-Prop $p       @('IncidentNumber','incidentNumber')
  $createdTimeUtc   = Get-Prop $p       @('CreatedTimeUtc','createdTimeUtc','CreatedTime','createdTime')
  $lastModifiedUtc  = Get-Prop $p       @('LastModifiedTimeUtc','lastModifiedTimeUtc')
  $lastActivityUtc  = Get-Prop $p       @('LastActivityTimeUtc','lastActivityTimeUtc')
  $statusBefore     = Get-Prop $p       @('Status','status')
  $severity         = Get-Prop $p       @('Severity','severity')
  $labelsBeforeRaw  = Get-Prop $p       @('Labels','labels')
  $ownerObj         = Get-Prop $p       @('Owner','owner')
  $owner            = $null

  # Owner normalisation
  if ($ownerObj) {
    # Try common shapes: AssignedTo, UserPrincipalName, Email/EmailAddress
    $owner = Get-Prop $ownerObj @('AssignedTo','UserPrincipalName','Email','EmailAddress','Name')
  }

  # Labels normalisation to array
  $labelsBefore = @()
  if ($labelsBeforeRaw -is [System.Collections.IEnumerable]) {
    foreach ($l in $labelsBeforeRaw) {
      # Labels can be either strings or objects with Name/Value
      $labelName = Get-Prop $l @('Name','name')
      if ($labelName) { $labelsBefore += "$labelName" }
      elseif ($l) { $labelsBefore += "$l" }
    }
  } elseif ($labelsBeforeRaw) {
    $labelsBefore = @("$labelsBeforeRaw")
  }

  # Merge labels with requested tag; de-dupe
  $labelsAfter = ($labelsBefore + $Tag | Where-Object { $_ } | Select-Object -Unique)

  # Timestamped comment
  $tsUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $finalComment = "$BaseComment (Closure timestamp: $tsUtc)"

  $log = [ordered]@{
    TimestampUTC         = $tsUtc
    IncidentId           = $id
    IncidentName         = $incidentName
    IncidentNumber       = $incidentNumber
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
  } catch {
    $log.Result = "FAILED"
    $log.Error  = $_.Exception.Message
    Write-Warning "Failed to update $title ($id): $($log.Error)"
  } finally {
    $results += New-Object psobject -Property $log
  }
}

# Always try to write CSV, even if $results is empty
try {
  $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
  Write-Host "Audit log written to $CsvPath"
} catch {
  Write-Warning "Failed to write CSV to $CsvPath: $($_.Exception.Message)"
}

# Console table
$results |
  Select-Object TimestampUTC, IncidentId, IncidentName, IncidentNumber, Title, CreatedTimeUtc, LastModifiedTimeUtc, LastActivityTimeUtc, Severity, Owner, Result, StatusBefore, StatusAfter, Classification |
  Format-Table -AutoSize

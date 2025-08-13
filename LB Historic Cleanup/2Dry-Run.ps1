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
<#
Close Sentinel incidents in a date window, classify as Undetermined, add a tag, and log to CSV.
Works on Windows PowerShell 5.1 and PowerShell 7+.
#>

<#
Close Microsoft Sentinel incidents in a date window, classify as Undetermined, add a tag, and log to CSV.
- Works on Windows PowerShell 5.1 and PowerShell 7+
- Defaults CSV to C:\sentinel-close-log_yyyyMMdd_HHmmss.csv
- Fields logged: Id, Name, Number, Title, Created/Modified/Activity times, Severity, Owner, Status (before/after), Labels, etc.
- Uses server-side OData filter and supports -WhatIf for dry runs.

REQUIRES:
  Az.Accounts, Az.OperationalInsights, Az.SecurityInsights
#>

<#
Close Microsoft Sentinel incidents in a date window, classify as Undetermined, add a tag,
and write BOTH a CSV and a TXT (identical comma-separated data).
- PowerShell 5.1 and 7+ compatible
- Defaults CSV to C:\sentinel-close-log_yyyyMMdd_HHmmss.csv
- TXT defaults to same basename as CSV with .txt extension, unless -TxtPath is provided
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [Parameter(Mandatory)][string]$ResourceGroup,
  [Parameter(Mandatory)][string]$Workspace,

  # Use ISO 8601 UTC e.g. 2025-03-01T00:00:00Z
  [Parameter(Mandatory)][string]$From,
  [Parameter(Mandatory)][string]$To,

  [string]$Classification = "Undetermined",
  [Parameter(Mandatory)][string]$Tag,

  [Parameter(Mandatory)][string]$BaseComment,

  # Optional. If omitted, defaults to C:\sentinel-close-log_yyyyMMdd_HHmmss.csv
  [string]$CsvPath,

  # Optional. If omitted, defaults to same basename as CSV with .txt extension
  [string]$TxtPath
)

# -------- Defaults & validation --------
# Default CSV path (C:\) if not provided
if (-not $CsvPath -or [string]::IsNullOrWhiteSpace($CsvPath)) {
  $CsvPath = Join-Path -Path 'C:\Temp' -ChildPath ("sentinel-close-log_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

# If TxtPath not provided, mirror CSV basename with .txt
if (-not $TxtPath -or [string]::IsNullOrWhiteSpace($TxtPath)) {
  $TxtPath = [System.IO.Path]::ChangeExtension($CsvPath, '.txt')
}

# Ensure CSV folder exists (handle bare filenames)
$csvDir = Split-Path -Path $CsvPath -Parent
if (-not $csvDir -or [string]::IsNullOrWhiteSpace($csvDir)) {
  $csvDir = (Get-Location).Path
  $CsvPath = Join-Path -Path $csvDir -ChildPath (Split-Path -Path $CsvPath -Leaf)
}
if (-not (Test-Path $csvDir)) {
  New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
}

# Ensure TXT folder exists (independent of CSV; supports separate drive/folder)
$txtDir = Split-Path -Path $TxtPath -Parent
if (-not $txtDir -or [string]::IsNullOrWhiteSpace($txtDir)) {
  # If TxtPath provided without a folder, use CSV folder by default
  $TxtPath = Join-Path -Path $csvDir -ChildPath (Split-Path -Path $TxtPath -Leaf)
  $txtDir  = $csvDir
}
if (-not (Test-Path $txtDir)) {
  New-Item -ItemType Directory -Path $txtDir -Force | Out-Null
}

# Parse dates
try {
  [datetime]$fromDt = [datetime]::Parse($From)
  [datetime]$toDt   = [datetime]::Parse($To)
} catch {
  throw ("From/To must be valid timestamps (e.g. 2025-03-01T00:00:00Z). Error: {0}" -f $_.Exception.Message)
}
if ($toDt -le $fromDt) { throw "Parameter -To must be greater than -From." }

# -------- Helpers --------
function Get-Prop {
  param($obj, [string[]]$paths)
  foreach ($p in $paths) {
    $o = $obj
    foreach ($seg in ($p -split '\.')) {
      if ($null -eq $o) { break }
      try {
        $o = $o | Select-Object -ExpandProperty $seg -ErrorAction Stop
      } catch {
        $o = $null
        break
      }
    }
    if ($null -ne $o -and "$o" -ne "") { return $o }
  }
  return $null
}

# Unified writer: exports rows to a path as CSV; if no rows, writes header-only file.
$CsvColumns = @(
  'TimestampUTC','IncidentId','IncidentName','IncidentNumber','Title',
  'CreatedTimeUtc','LastModifiedTimeUtc','LastActivityTimeUtc','Severity','Owner',
  'Result','StatusBefore','StatusAfter','Classification','LabelsBefore','LabelsAfter','CommentSnippet','Error'
)

function Write-TableFile {
  param([array]$Rows, [string]$Path, [string[]]$Columns)
  try {
    if ($Rows -and $Rows.Count -gt 0) {
      $Rows | Select-Object $Columns | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    } else {
      # Header-only so a file always exists
      ($Columns -join ',') | Set-Content -Path $Path -Encoding UTF8
    }
    Write-Host ("File written to {0}" -f $Path)
  } catch {
    Write-Warning ("Failed to write file to {0}: {1}" -f $Path, $_.Exception.Message)
  }
}

# -------- Query & update --------
$filter = "properties/createdTimeUtc ge $($fromDt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) and properties/createdTimeUtc lt $($toDt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) and properties/status ne 'Closed'"
Write-Verbose ("OData filter: {0}" -f $filter)

$results   = @()
$incidents = Get-AzSentinelIncident -ResourceGroupName $ResourceGroup -WorkspaceName $Workspace -Filter $filter

if (-not $incidents) {
  Write-Warning "No incidents matched the filter. Writing header-only CSV/TXT."
}

foreach ($incident in $incidents) {
  $p = $incident.Properties
  if (-not $p) { $p = $incident }

  $id               = Get-Prop $incident @('Name','Id')
  $title            = Get-Prop $p       @('Title','title')
  #$incidentName     = Get-Prop $p       @('IncidentName','incidentName','Name','name')
  $incidentNumber   = Get-Prop $p       @('IncidentNumber','incidentNumber')
  $createdTimeUtc   = Get-Prop $p       @('CreatedTimeUtc','createdTimeUtc','CreatedTime','createdTime')
  $lastModifiedUtc  = Get-Prop $p       @('LastModifiedTimeUtc','lastModifiedTimeUtc')
  $lastActivityUtc  = Get-Prop $p       @('LastActivityTimeUtc','lastActivityTimeUtc')
  $statusBefore     = Get-Prop $p       @('Status','status')
  $severity         = Get-Prop $p       @('Severity','severity')
  $labelsBeforeRaw  = Get-Prop $p       @('Labels','labels')
  $ownerObj         = Get-Prop $p       @('Owner','owner')

  # Owner normalisation (try common shapes)
  $owner = $null
  if ($ownerObj) {
    $owner = Get-Prop $ownerObj @('AssignedTo','UserPrincipalName','Email','EmailAddress','Name')
  }

  # Labels → array of strings
  $labelsBefore = @()
  if ($labelsBeforeRaw -is [System.Collections.IEnumerable]) {
    foreach ($l in $labelsBeforeRaw) {
      $labelName = Get-Prop $l @('Name','name')
      if ($labelName) { $labelsBefore += "$labelName" }
      elseif ($l)     { $labelsBefore += "$l" }
    }
  } elseif ($labelsBeforeRaw) {
    $labelsBefore = @("$labelsBeforeRaw")
  }
  $labelsAfter = ($labelsBefore + $Tag | Where-Object { $_ } | Select-Object -Unique)

  # Comment with closure timestamp (UTC)
  $tsUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $finalComment = "$BaseComment (Closure timestamp: $tsUtc)"

  $log = [ordered]@{
    TimestampUTC         = $tsUtc
    IncidentId           = $id
#    IncidentName         = $incidentName
    IncidentNumber       = $incidentNumber
    Title                = $title
    CreatedTimeUtc       = $createdTimeUtc
    LastModifiedTimeUtc  = $lastModifiedUtc
    LastActivityTimeUtc  = $lastActivityTimeUtc
    Severity             = $severity
    Owner                = $owner
    Result               = "PENDING"
    StatusBefore         = $statusBefore
    StatusAfter          = "Closed"
    Classification       = $Classification
    LabelsBefore         = ($labelsBefore -join ";")
    LabelsAfter          = ($labelsAfter  -join ";")
    CommentSnippet       = ($finalComment.Substring(0, [Math]::Min(120, $finalComment.Length)))
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
    Write-Warning ("Failed to update {0} ({1}): {2}" -f $title, $id, $_.Exception.Message)
  } finally {
    $results += New-Object psobject -Property $log
  }
}

# -------- Persist BOTH files (CSV + TXT mirror) & render table --------

Write-Host ("[DEBUG] CSV path: {0}" -f $CsvPath)
Write-Host ("[DEBUG] TXT path: {0}" -f $TxtPath)
Write-TableFile -Rows $results -Path $CsvPath -Columns $CsvColumns
Write-TableFile -Rows $results -Path $TxtPath -Columns $CsvColumns

if (Test-Path $CsvPath) {
    Write-Host ("[DEBUG] CSV file exists: {0}" -f $CsvPath)
} else {
    Write-Warning ("[DEBUG] CSV file NOT found: {0}" -f $CsvPath)
}
if (Test-Path $TxtPath) {
    Write-Host ("[DEBUG] TXT file exists: {0}" -f $TxtPath)
} else {
    Write-Warning ("[DEBUG] TXT file NOT found: {0}" -f $TxtPath)
}

Write-Host ("CSV written to {0}" -f $CsvPath)
Write-Host ("TXT written to {0}" -f $TxtPath)

$results |
  Select-Object TimestampUTC, IncidentId, IncidentName, IncidentNumber, Title, CreatedTimeUtc, LastModifiedTimeUtc, LastActivityTimeUtc, Severity, Owner, Result, StatusBefore, StatusAfter, Classification |
  Format-Table -AutoSize

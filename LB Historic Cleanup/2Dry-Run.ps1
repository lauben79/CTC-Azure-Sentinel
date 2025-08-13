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
Close Microsoft Sentinel incidents in a date window, classify as Undetermined, add a tag, and log to CSV + TXT.
- Works on Windows PowerShell 5.1 and PowerShell 7+
- Defaults outputs to C:\sentinel-close-log_yyyyMMdd_HHmmss.csv and .txt
- Server-side OData filter; supports -WhatIf for dry runs
- Robust property handling across Az.SecurityInsights versions
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
  [string]$CsvPath
)

# -------- Defaults & validation --------
# Default CSV path if not provided (C:\)
if (-not $CsvPath -or [string]::IsNullOrWhiteSpace($CsvPath)) {
  $CsvPath = Join-Path -Path 'C:\Temp\' -ChildPath ("sentinel-close-log_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

# Derive TXT path (same base name)
$TxtPath = [System.IO.Path]::ChangeExtension($CsvPath, '.txt')

# Ensure output folder exists
$csvDir = Split-Path -Path $CsvPath -Parent
if (-not $csvDir -or [string]::IsNullOrWhiteSpace($csvDir)) {
  $csvDir = (Get-Location).Path
  $CsvPath = Join-Path -Path $csvDir -ChildPath (Split-Path -Path $CsvPath -Leaf)
  $TxtPath = [System.IO.Path]::ChangeExtension($CsvPath, '.txt')
}
if (-not (Test-Path $csvDir)) {
  New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
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

# Define the output schema once so we can write header-only CSVs
$CsvColumns = @(
  'TimestampUTC','IncidentId','IncidentName','IncidentNumber','Title',
  'CreatedTimeUtc','LastModifiedTimeUtc','LastActivityTimeUtc','Severity','Owner',
  'Result','StatusBefore','StatusAfter','Classification','LabelsBefore','LabelsAfter','CommentSnippet','Error'
)

function Write-CsvSafe {
  param([array]$Rows, [string]$Path, [string[]]$Columns)
  try {
    if ($Rows -and $Rows.Count -gt 0) {
      $Rows | Select-Object $Columns | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    } else {
      # Write header-only CSV so a file always exists
      ($Columns -join ',') | Set-Content -Path $Path -Encoding UTF8
    }
    Write-Host ("Audit CSV written to {0}" -f $Path)
  } catch {
    Write-Warning ("Failed to write CSV to {0}: {1}" -f $Path, $_.Exception.Message)
  }
}

function Write-TxtLog {
  param([array]$Rows, [string]$Path, [string]$FilterText)
  try {
    $nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $lines = @()
    $lines += "Microsoft Sentinel Incident Closure Run"
    $lines += "RunTimestampUTC : $nowUtc"
    $lines += "ResourceGroup   : $ResourceGroup"
    $lines += "Workspace       : $Workspace"
    $lines += "From            : $($fromDt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    $lines += "To              : $($toDt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    $lines += "Classification  : $Classification"
    $lines += "Tag             : $Tag"
    $lines += "Filter          : $FilterText"
    $lines += "MatchedCount    : $($Rows.Count)"
    $lines += ("-"*80)

    foreach ($r in $Rows) {
      $lines += ("Id={0} | Name={1} | Title={2} | Sev={3} | CreatedUtc={4} | Result={5}" -f `
        $r.IncidentId, $r.IncidentName, $r.Title, $r.Severity, $r.CreatedTimeUtc, $r.Result)
      if ($r.Error) { $lines += ("  Error: {0}" -f $r.Error) }
    }
    $lines += ("-"*80)
    $lines += "End of run."

    Set-Content -Path $Path -Value $lines -Encoding UTF8
    Write-Host ("Text log written to {0}" -f $Path)
  } catch {
    Write-Warning ("Failed to write TXT log to {0}: {1}" -f $Path, $_.Exception.Message)
  }
}

# -------- Query & update --------
$filter = "properties/createdTimeUtc ge $($fromDt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) and properties/createdTimeUtc lt $($toDt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) and properties/status ne 'Closed'"
Write-Verbose ("OData filter: {0}" -f $filter)

$results   = @()
$incidents = Get-AzSentinelIncident -ResourceGroupName $ResourceGroup -WorkspaceName $Workspace -Filter $filter

if (-not $incidents) {
  Write-Warning "No incidents matched the filter. Continuing to write empty CSV/TXT logs."
}

foreach ($incident in $incidents) {
  $p = $incident.Properties
  if (-not $p) { $p = $incident }

  $id               = Get-Prop $incident @('Name','Id')
  $title            = Get-Prop $p       @('Title','title')
 # $incidentName     = Get-Prop $p       @('IncidentName','incidentName','Name','name')
  $incidentNumber   = Get-Prop $p       @('IncidentNumber','incidentNumber')
  $createdTimeUtc   = Get-Prop $p       @('CreatedTimeUtc','createdTimeUtc','CreatedTime','createdTime')
  $lastModifiedUtc  = Get-Prop $p       @('LastModifiedTimeUtc','lastModifiedTimeUtc')
  $lastActivityUtc  = Get-Prop $p       @('LastActivityTimeUtc','lastActivityTimeUtc')
  $statusBefore     = Get-Prop $p       @('Status','status')
  $severity         = Get-Prop $p       @('Severity','severity')
  $labelsBeforeRaw  = Get-Prop $p       @('Labels','labels')
  $ownerObj         = Get-Prop $p       @('Owner','owner')

  # Owner normalisation
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
    IncidentName         = $incidentName
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

# -------- Persist CSV + TXT & render table --------
Write-CsvSafe -Rows $results -Path $CsvPath -Columns $CsvColumns
Write-TxtLog  -Rows $results -Path $TxtPath -FilterText $filter

$results |
  Select-Object TimestampUTC, IncidentId, IncidentName, IncidentNumber, Title, CreatedTimeUtc, LastModifiedTimeUtc, LastActivityTimeUtc, Severity, Owner, Result, StatusBefore, StatusAfter, Classification |
  Format-Table -AutoSize
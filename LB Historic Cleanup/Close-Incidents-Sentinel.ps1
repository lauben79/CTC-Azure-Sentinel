<#
Close Microsoft Sentinel incidents in a date window, classify as Undetermined, add a tag,
and write BOTH a CSV and a TXT (identical comma-separated data).

- PowerShell 5.1 and 7+ compatible (no null-conditional operators)
- Defaults:
    ResourceGroup     = "RG-REPLACE"
    Workspace         = "WS-REPLACE"
    From              = "2025-03-01T00:00:00Z"
    To                = "2025-04-01T00:00:00Z"
    Classification    = "Undetermined"
    Tag               = "Historic"
    BaseComment       = "Historic alerts which have been agreed with the local Bacardi team can be closed, due to no additional detections or malicious activity identified. These will be used for correlation and cross checking of any future alerts."
    CsvPath           = C:\sentinel-close-log_yyyyMMdd_HHmmss.csv
    TxtPath           = <CsvPath with .txt extension>
REQUIRES: Az.Accounts, Az.OperationalInsights, Az.SecurityInsights

Usage

PS .\Close-Incidents-Sentinel.ps1 -Verbose -WhatIf

Then remove -WhatIf to action the changes. 

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  # --- Defaults you can edit below ---
  [string]$ResourceGroup   = "east-us-cybersecurity",
  [string]$Workspace       = "global-cyber-security",

  # ISO 8601 UTC
  [string]$From            = "2025-03-01T00:00:00Z",
  [string]$To              = "2025-04-01T00:00:00Z",

  [string]$Classification  = "Undetermined",
  [string]$Tag             = "Historic",

  [string]$BaseComment     = "Historic alerts which have been agreed with the local Bacardi team can be closed, due to no additional detections or malicious activity identified. These will be used for correlation and cross checking of any future alerts.",

  # Optional outputs (defaults applied below)
  [string]$CsvPath         = $null,
  [string]$TxtPath         = $null
)

# -------- Defaults & validation --------
# Default CSV path (C:\) if not provided
if (-not $CsvPath -or [string]::IsNullOrWhiteSpace($CsvPath)) {
  $CsvPath = Join-Path -Path 'C:\' -ChildPath ("sentinel-close-log_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
# TXT mirrors CSV basename by default
if (-not $TxtPath -or [string]::IsNullOrWhiteSpace($TxtPath)) {
  $TxtPath = [System.IO.Path]::ChangeExtension($CsvPath, '.txt')
}

# Ensure CSV folder exists (handle bare filenames)
$csvDir = Split-Path -Path $CsvPath -Parent
if (-not $csvDir -or [string]::IsNullOrWhiteSpace($csvDir)) {
  $csvDir  = (Get-Location).Path
  $CsvPath = Join-Path -Path $csvDir -ChildPath (Split-Path -Path $CsvPath -Leaf)
}
if (-not (Test-Path $csvDir)) {
  New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
}

# Ensure TXT folder exists (independent of CSV)
$txtDir = Split-Path -Path $TxtPath -Parent
if (-not $txtDir -or [string]::IsNullOrWhiteSpace($txtDir)) {
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

# -------- Detect Update-AzSentinelIncident quirks (ETag + Label(s) + Description) --------
$updateCmd = Get-Command Update-AzSentinelIncident -ErrorAction SilentlyContinue
$supportsETag  = $false; $etagParamName = $null
$labelParam    = $null   # will be 'Labels' or 'Label' (or $null if neither)
$supportsDesc  = $false
if ($updateCmd) {
  if ($updateCmd.Parameters.ContainsKey('ETag'))        { $supportsETag = $true; $etagParamName = 'ETag' }
  elseif ($updateCmd.Parameters.ContainsKey('IfMatch')) { $supportsETag = $true; $etagParamName = 'IfMatch' }
  if     ($updateCmd.Parameters.ContainsKey('Labels'))  { $labelParam = 'Labels' }
  elseif ($updateCmd.Parameters.ContainsKey('Label'))   { $labelParam = 'Label' }
  if     ($updateCmd.Parameters.ContainsKey('Description')) { $supportsDesc = $true }
}
$maxCommentLen = 1024   # conservative limit for classification comment

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
  $incidentName     = Get-Prop $p       @('IncidentName','incidentName','Name','name')
  $incidentNumber   = Get-Prop $p       @('IncidentNumber','incidentNumber')
  $createdTimeUtc   = Get-Prop $p       @('CreatedTimeUtc','createdTimeUtc','CreatedTime','createdTime')
  $lastModifiedUtc  = Get-Prop $p       @('LastModifiedTimeUtc','lastModifiedTimeUtc')
  $lastActivityUtc  = Get-Prop $p       @('LastActivityTimeUtc','lastActivityTimeUtc')
  $statusBefore     = Get-Prop $p       @('Status','status')
  $severity         = Get-Prop $p       @('Severity','severity')
  $labelsBeforeRaw  = Get-Prop $p       @('Labels','labels')
  $ownerObj         = Get-Prop $p       @('Owner','owner')
  $currentEtag      = Get-Prop $incident @('Etag','etag','Properties.Etag','properties.etag')
  $description      = Get-Prop $p       @('Description','description','IncidentDescription','incidentDescription')

  # Safe fallbacks (avoid empty required fields)
  if (-not $title -or [string]::IsNullOrWhiteSpace($title)) { $title = ("Incident {0}" -f $id) }
  if (-not $severity -or [string]::IsNullOrWhiteSpace($severity)) { $severity = 'Low' }

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

  # Comment with closure timestamp (UTC) and safe length
  $tsUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $finalComment = "$BaseComment (Closure timestamp: $tsUtc)"
  if ($finalComment.Length -gt $maxCommentLen) {
    $finalComment = $finalComment.Substring(0, $maxCommentLen)
  }

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

      # Build base args (include Title/Severity; add Description if supported)
      $baseArgs = @{
        ResourceGroupName     = $ResourceGroup
        WorkspaceName         = $Workspace
        IncidentId            = $id
        Status                = 'Closed'
        Classification        = $Classification
        ClassificationComment = $finalComment
        Title                 = $title
        Severity              = $severity
        ErrorAction           = 'Stop'
      }
      if ($supportsDesc -and $description) { $baseArgs['Description'] = $description }

      # Pick the correct label parameter and shape
      if     ($labelParam -eq 'Labels') { $baseArgs['Labels'] = $labelsAfter } # string[]
      elseif ($labelParam -eq 'Label')  { $baseArgs['Label']  = ($labelsAfter | ForEach-Object { @{ Name = $_ } }) } # IIncidentLabel[]

      # If the cmdlet supports If-Match/ETag and we have an ETag, send it on the first go
      if ($supportsETag -and $etagParamName -and $currentEtag) {
        $baseArgs[$etagParamName] = $currentEtag
      }

      $attempted = $false
      try {
        Update-AzSentinelIncident @baseArgs | Out-Null
        $log.Result = "UPDATED"
        $attempted = $true
      } catch {
        # Extract errors safely (PS 5.1)
        $msg    = $_.Exception.Message
        $detail = $null; if ($_.ErrorDetails) { try { if ($_.ErrorDetails.Message) { $detail = $_.ErrorDetails.Message } } catch {} }
        $http   = $null; $body = $null
        if ($_.Exception -and $_.Exception.Response) {
          try { $http = $_.Exception.Response.StatusCode } catch {}
          try { $body = $_.Exception.Response.Content } catch {}
        }
        $composed = @($msg, $detail, $http, $body) -join " | "

        if ($composed -match '412|Precondition|etag') {
          if ($supportsETag -and $etagParamName) {
            $forceArgs = $baseArgs.Clone()
            $forceArgs[$etagParamName] = '*'
            try {
              Update-AzSentinelIncident @forceArgs | Out-Null
              $log.Result = "UPDATED(ETAG-*)"
              $attempted = $true
            } catch {
              $emsg    = $_.Exception.Message
              $edetail = $null; if ($_.ErrorDetails) { try { if ($_.ErrorDetails.Message) { $edetail = $_.ErrorDetails.Message } } catch {} }
              $ehttp   = $null; $ebody = $null
              if ($_.Exception -and $_.Exception.Response) {
                try { $ehttp = $_.Exception.Response.StatusCode } catch {}
                try { $ebody = $_.Exception.Response.Content } catch {}
              }
              $log.Result = "FAILED"
              $log.Error  = (@($emsg, $edetail, $ehttp, $ebody) -join " | ")
            }
          } else {
            $log.Result = "FAILED"
            $log.Error  = "Concurrency/ETag error but cmdlet lacks ETag/IfMatch support. Details: $composed"
          }
        }
        elseif ($composed -match '403|Authorization|Forbidden|Insufficient|NotAuthorized') {
          $log.Result = "FAILED"
          $log.Error  = "Permission issue. Ensure Microsoft Sentinel Responder or Contributor on the workspace. Details: $composed"
        }
        elseif ($composed -match '429|throttle|Too Many Requests') {
          Start-Sleep -Seconds 2
          try {
            Update-AzSentinelIncident @baseArgs | Out-Null
            $log.Result = "UPDATED(RETRY)"
            $attempted = $true
          } catch {
            $emsg2    = $_.Exception.Message
            $edetail2 = $null; if ($_.ErrorDetails) { try { if ($_.ErrorDetails.Message) { $edetail2 = $_.ErrorDetails.Message } } catch {} }
            $ehttp2   = $null; $ebody2 = $null
            if ($_.Exception -and $_.Exception.Response) {
              try { $ehttp2 = $_.Exception.Response.StatusCode } catch {}
              try { $ebody2 = $_.Exception.Response.Content } catch {}
            }
            $log.Result = "FAILED"
            $log.Error  = (@($emsg2, $edetail2, $ehttp2, $ebody2) -join " | ")
          }
        }
        else {
          $log.Result = "FAILED"
          $log.Error  = $composed
        }
      }

      if ($attempted -and $log.Result -like "UPDATED*") {
        Start-Sleep -Milliseconds 200  # pacing
      }
    } else {
      $log.Result = "WHATIF"
    }
  } catch {
    # Final catch with PS 5.1-safe extraction
    $emsg3    = $_.Exception.Message
    $edetail3 = $null; if ($_.ErrorDetails) { try { if ($_.ErrorDetails.Message) { $edetail3 = $_.ErrorDetails.Message } } catch {} }
    $ehttp3   = $null; $ebody3 = $null
    if ($_.Exception -and $_.Exception.Response) {
      try { $ehttp3 = $_.Exception.Response.StatusCode } catch {}
      try { $ebody3 = $_.Exception.Response.Content } catch {}
    }
    $log.Result = "FAILED"
    $log.Error  = (@($emsg3, $edetail3, $ehttp3, $ebody3) -join " | ")
    Write-Warning ("Failed to update {0} ({1}): {2}" -f $title, $id, $log.Error)
  } finally {
    $results += New-Object psobject -Property $log
  }
}

# -------- Persist BOTH files (CSV + TXT mirror) & render table --------
function Write-TableMirror { param([array]$Rows,[string]$Csv,[string]$Txt,[string[]]$Cols) Write-TableFile -Rows $Rows -Path $Csv -Columns $Cols; Write-TableFile -Rows $Rows -Path $Txt -Columns $Cols }
Write-TableMirror -Rows $results -Csv $CsvPath -Txt $TxtPath -Cols $CsvColumns

Write-Host ("CSV written to {0}" -f $CsvPath)
Write-Host ("TXT written to {0}" -f $TxtPath)

$results |
  Select-Object TimestampUTC, IncidentId, IncidentName, IncidentNumber, Title, CreatedTimeUtc, LastModifiedTimeUtc, LastActivityTimeUtc, Severity, Owner, Result, StatusBefore, StatusAfter, Classification |
  Format-Table -AutoSize

  # Pick the columns once
$sel = $results |
  Select-Object TimestampUTC, IncidentId, Title, CreatedTimeUtc, LastModifiedTimeUtc, `
                LastActivityTimeUtc, Severity, Owner, Result, StatusBefore, StatusAfter, Classification

# Timestamps & output paths (edit as needed)
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$csv   = Join-Path $PWD "incidents_$stamp.csv"
$txt   = Join-Path $PWD "incidents_$stamp.txt"

# 1) CSV (best for Excel/analysis) – don't use Format-Table for this
$sel | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

# 2) Pretty text table – do format here, then write to file
$sel |
  Format-Table -AutoSize |
  Out-String -Width 4096 |    # avoid truncation; use a large width
  Set-Content -Path $txt -Encoding UTF8

"$csv"
"$txt"
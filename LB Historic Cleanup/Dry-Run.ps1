# =========================
# CONFIGURATION
# =========================
$SubscriptionId = "bfdd0a4a-b14b-466c-96f0-47620227e40b"
$ResourceGroup  = "east-us-cybersecurity"
$WorkspaceName  = "global-cyber-security"

$StartDate = Get-Date "2025-03-01T00:00:00Z"
$EndDate   = Get-Date "2025-04-01T23:59:59Z"

$HistoricComment = "Historic alerts which have been agreed with the local Bacardi team can be closed, due to no additional detections or malicious activity identified. These will be used for correlation and cross checking of any future alerts."
$HistoricTag = "Historic"

# =========================
# LOGIN & CONTEXT
# =========================
Connect-AzAccount
Set-AzContext -SubscriptionId $SubscriptionId

# =========================
# FETCH INCIDENTS
# =========================
$incidents = Get-AzSentinelIncident -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName |
    Where-Object {
        ($_.Properties.CreatedTimeUtc -ge $StartDate) -and
        ($_.Properties.CreatedTimeUtc -le $EndDate) -and
        ($_.Properties.Status -ne "Closed")
    }

Write-Host "📋 Found $($incidents.Count) incidents in date range that would be closed:" -ForegroundColor Cyan
Write-Host "-----------------------------------------------------------------------"

 foreach ($incident in $incidents) {
     $existingLabels = $incident.Properties.Labels
     if ($existingLabels -notcontains $HistoricTag) {
         $existingLabels += $HistoricTag
     }

     Write-Host "Incident ID: $($incident.Name)" -ForegroundColor Yellow
     Write-Host "  Title: $($incident.Properties.Title)"
     Write-Host "  Created: $($incident.Properties.CreatedTimeUtc)"
     Write-Host "  Existing Tags: $($incident.Properties.Labels -join ', ')"
     Write-Host "  New Tags: $($existingLabels -join ', ')"
     Write-Host "  Close Comment: $HistoricComment"
     Write-Host " "
 }

 Write-Host "✅ Dry-run complete. No incidents were modified."
 Write-Host "When ready, switch to the live script to apply changes""
 
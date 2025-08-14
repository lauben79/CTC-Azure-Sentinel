<#
.SYNOPSIS
Closes only Microsoft Sentinel incidents matching a specific Title.
.DESCRIPTION
Fetches open incidents, filters by Title, and closes the matching ones with retries and pagination.
#>

# Configuration
$config = @{
    ResourceGroupName = "east-us-cybersecurity"
    WorkspaceName    = "global-cyber-security"
    SubscriptionId   = "bfdd0a4a-b14b-466c-96f0-47620227e40b"
    PageSize          = 100            # Reduced for better pagination handling
    RetryAttempts     = 2              # Retries per incident
    DelayBetweenCalls = 2              # Seconds between API calls
    TargetTitle       = "<sentinel_incident_title>" # Title of incident to close
}

# Initialize counters
$totalClosed = 0
$failedIncidents = [System.Collections.Generic.List[string]]::new()

function Close-AllIncidents {
    $continue = $true
    $nextLink = $null
    
    while ($continue) {
        try {
            # Get incidents with proper pagination handling
            if ($nextLink) {
                $incidents = Get-AzSentinelIncident -NextLink $nextLink
            }
            else {
                $incidents = Get-AzSentinelIncident -ResourceGroupName $config.ResourceGroupName `
                                                  -WorkspaceName $config.WorkspaceName `
                                                  -Filter "properties/status eq 'New'" `
                                                  -Top $config.PageSize
            }

            if (-not $incidents -or $incidents.Count -eq 0) { 
                $continue = $false
                break 
            }

            # Store nextLink for pagination
            $nextLink = $incidents.NextLink

            # Process incidents
            foreach ($incident in $incidents) {
                $retryCount = 0
                $closed = $false

                while ($retryCount -lt $config.RetryAttempts -and -not $closed) {
                    try {
                        Update-AzSentinelIncident -Id $incident.Name `
                            -ResourceGroupName $config.ResourceGroupName `
                            -WorkspaceName $config.WorkspaceName `
                            -SubscriptionId $config.SubscriptionId `
                            -Status Closed `
                            -Confirm:$false `
                            -Severity $incident.Severity `
                            -Classification Undetermined `
                            -Title $incident.Title `
                            -ErrorAction Stop
                        
                        $script:totalClosed++
                        $closed = $true
                        Write-Host "Closed incident: $($incident.Name)" -ForegroundColor Green
                    } catch {
                        $retryCount++
                        if ($retryCount -ge $config.RetryAttempts) {
                            $script:failedIncidents.Add($incident.Name)
                            Write-Host "Failed to close incident: $($incident.Name) - $($_.Exception.Message)" -ForegroundColor Red
                        }
                        Start-Sleep -Milliseconds 500
                    }
                }
            }

            Write-Host "Processed $($incidents.Count) incidents | Total closed: $totalClosed"
            
            # Add delay between API calls
            Start-Sleep -Seconds $config.DelayBetweenCalls

        } catch {
            Write-Host "Error processing batch: $_" -ForegroundColor Red
            $continue = $false
        }
    }
}

# Main execution
Write-Host "Starting bulk incident closure process..." -ForegroundColor Cyan
Write-Host "Configuration:"
Write-Host "- Page Size: $($config.PageSize)"
Write-Host "- Retry Attempts: $($config.RetryAttempts)"
Write-Host "- Delay Between Calls: $($config.DelayBetweenCalls)s"
Write-Host ""

Close-AllIncidents

# Results
Write-Host @"
============================================
Bulk closure process completed
Total incidents closed: $totalClosed
Failed to close: $($failedIncidents.Count)
============================================
"@ -ForegroundColor Cyan

if ($failedIncidents.Count -gt 0) {
    Write-Host "Failed incident IDs:" -ForegroundColor Yellow
    $failedIncidents | ForEach-Object { Write-Host "- $_" }
}

Write-Host "Process completed at $(Get-Date)" -ForegroundColor Cyan
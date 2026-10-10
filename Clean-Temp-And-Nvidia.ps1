<#
.SYNOPSIS
    Secure System Maintenance & Storage Cleanup Script
.DESCRIPTION
    Safely purges strictly defined temporary directories and orphaned driver installers.
    Enforces strict path whitelisting, symlink protection, and age filters.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'

# 1. Strict Path Whitelist (Only exact approved locations)
$TargetSpecs = @(
    @{
        Description = "User Local Temp (files older than 24h)"
        Path        = "$env:LOCALAPPDATA\Temp"
        MinAgeHours = 24
        PurgeFiles  = $true
        PurgeDirs   = $true
    },
    @{
        Description = "Windows System Temp"
        Path        = "$env:SystemRoot\Temp"
        MinAgeHours = 24
        PurgeFiles  = $true
        PurgeDirs   = $true
    },
    @{
        Description = "NVIDIA Driver Download Cache"
        Path        = "$env:ProgramData\NVIDIA Corporation\Downloader"
        MinAgeHours = 0
        PurgeFiles  = $true
        PurgeDirs   = $true
    },
    @{
        Description = "NVIDIA App OTA Artifacts"
        Path        = "$env:ProgramData\NVIDIA Corporation\NVIDIA App\UpdateFramework\ota-artifacts"
        MinAgeHours = 0
        PurgeFiles  = $true
        PurgeDirs   = $true
    }
)

$TotalReclaimed = 0
$Now = Get-Date

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Starting Secure Storage Maintenance Run" -ForegroundColor Cyan
Write-Host "Timestamp: $($Now.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

foreach ($spec in $TargetSpecs) {
    $dir = $spec.Path
    if (-not (Test-Path -LiteralPath $dir)) {
        continue
    }

    Write-Host "`nProcessing: $($spec.Description)" -ForegroundColor Yellow
    Write-Host "Directory:  $dir" -ForegroundColor Gray

    $cutoff = if ($spec.MinAgeHours -gt 0) { $Now.AddHours(-$spec.MinAgeHours) } else { $Now }

    # Query items safely using LiteralPath to prevent wildcard injection
    $items = Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue

    foreach ($item in $items) {
        # Anti-hijack check: never follow reparse points / symlinks / junction points
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            continue
        }

        # Age verification check
        if ($spec.MinAgeHours -gt 0 -and $item.LastWriteTime -gt $cutoff) {
            continue
        }

        try {
            $itemSize = 0
            if (-not $item.PSIsContainer) {
                if ($spec.PurgeFiles) {
                    $itemSize = $item.Length
                    Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
                    $TotalReclaimed += $itemSize
                }
            } else {
                if ($spec.PurgeDirs) {
                    # Measure directory size before deletion
                    $dirSize = (Get-ChildItem -LiteralPath $item.FullName -Recurse -Force -ErrorAction SilentlyContinue |
                                Where-Object { -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) } |
                                Measure-Object -Property Length -Sum).Sum
                    if ($dirSize) { $itemSize = $dirSize }

                    Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
                    $TotalReclaimed += $itemSize
                }
            }
        } catch {
            # File is in active use by a running process or permission locked; skip safely
            continue
        }
    }
}

$ReclaimedMB = [math]::Round($TotalReclaimed / 1MB, 2)
$ReclaimedGB = [math]::Round($TotalReclaimed / 1GB, 2)

Write-Host "`n==========================================" -ForegroundColor Green
Write-Host "Cleanup Complete!" -ForegroundColor Green
Write-Host "Reclaimed Space: $ReclaimedMB MB ($ReclaimedGB GB)" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green

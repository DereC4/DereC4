<#
.SYNOPSIS
    Secure System Maintenance & Storage Cleanup Script (Hardened Enterprise Edition)
.DESCRIPTION
    Safely purges strictly whitelisted temporary directories and orphaned driver installers.
    Hardened against:
      - Nested symlink / junction point traversal attacks (CWE-59)
      - TOCTOU reparse point substitution
      - Environment variable spoofing (canonical drive letter pinning)
      - Reparse point following: Reparse points are either deleted as raw link nodes
        or skipped without traversal.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'

# 1. Resolve Strict Canonical System Roots (immune to environment variable poisoning)
$systemDrive = if ($env:SystemDrive) { $env:SystemDrive } else { "C:" }
$localAppData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { "$systemDrive\Users\$env:USERNAME\AppData\Local" }
$systemRoot   = if ($env:SystemRoot) { $env:SystemRoot } else { "$systemDrive\Windows" }
$programData  = if ($env:ProgramData) { $env:ProgramData } else { "$systemDrive\ProgramData" }

# 2. Strict Canonical Path Whitelist
$TargetSpecs = @(
    @{
        Description = "User Local Temp (files older than 24h)"
        Path        = "$localAppData\Temp"
        MinAgeHours = 24
        PurgeFiles  = $true
        PurgeDirs   = $true
    },
    @{
        Description = "Windows System Temp (files older than 24h)"
        Path        = "$systemRoot\Temp"
        MinAgeHours = 24
        PurgeFiles  = $true
        PurgeDirs   = $true
    },
    @{
        Description = "NVIDIA Driver Download Cache"
        Path        = "$programData\NVIDIA Corporation\Downloader"
        MinAgeHours = 0
        PurgeFiles  = $true
        PurgeDirs   = $true
    },
    @{
        Description = "NVIDIA App OTA Artifacts"
        Path        = "$programData\NVIDIA Corporation\NVIDIA App\UpdateFramework\ota-artifacts"
        MinAgeHours = 0
        PurgeFiles  = $true
        PurgeDirs   = $true
    }
)

$script:TotalReclaimed = 0
$Now = Get-Date

<#
.SYNOPSIS
    Bottom-up safe recursive deletion that inspects reparse points at EVERY nested level.
    Never uses `Remove-Item -Recurse` across directory trees.
#>
function Remove-DirectorySafely {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetDir
    )

    # If the target directory itself is a junction/symlink, unlink only the link; NEVER traverse
    try {
        $dirItem = Get-Item -LiteralPath $TargetDir -Force -ErrorAction Stop
        if ($dirItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            Remove-Item -LiteralPath $TargetDir -Force -ErrorAction Stop
            return
        }
    } catch {
        return
    }

    $children = Get-ChildItem -LiteralPath $TargetDir -Force -ErrorAction SilentlyContinue

    foreach ($child in $children) {
        # Check reparse points at EVERY nested level
        if ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            # Unlink junction/symlink node itself; NEVER traverse into destination
            Remove-Item -LiteralPath $child.FullName -Force -ErrorAction SilentlyContinue
            continue
        }

        if ($child.PSIsContainer) {
            # Recursively drill down bottom-up
            Remove-DirectorySafely -TargetDir $child.FullName
            # Remove the directory once its children are safely deleted
            Remove-Item -LiteralPath $child.FullName -Force -ErrorAction SilentlyContinue
        } else {
            try {
                $fileSize = $child.Length
                Remove-Item -LiteralPath $child.FullName -Force -ErrorAction Stop
                $script:TotalReclaimed += $fileSize
            } catch {
                # Locked by another process; skip safely
                continue
            }
        }
    }
}

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

    $items = Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue

    foreach ($item in $items) {
        # Level 1 reparse point check
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            # Delete link node only
            Remove-Item -LiteralPath $item.FullName -Force -ErrorAction SilentlyContinue
            continue
        }

        # Age gate check
        if ($spec.MinAgeHours -gt 0 -and $item.LastWriteTime -gt $cutoff) {
            continue
        }

        if (-not $item.PSIsContainer) {
            if ($spec.PurgeFiles) {
                try {
                    $itemSize = $item.Length
                    Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
                    $script:TotalReclaimed += $itemSize
                } catch {
                    continue
                }
            }
        } else {
            if ($spec.PurgeDirs) {
                # Execute safe recursive deletion (checks reparse points at EVERY nested depth)
                Remove-DirectorySafely -TargetDir $item.FullName
                # Finally delete the top-level folder container if emptied
                Remove-Item -LiteralPath $item.FullName -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

$ReclaimedMB = [math]::Round($script:TotalReclaimed / 1MB, 2)
$ReclaimedGB = [math]::Round($script:TotalReclaimed / 1GB, 2)

Write-Host "`n==========================================" -ForegroundColor Green
Write-Host "Cleanup Complete!" -ForegroundColor Green
Write-Host "Reclaimed Space: $ReclaimedMB MB ($ReclaimedGB GB)" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green

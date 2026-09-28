function Remove-McRun {
    # Get-ChildItem: Finds all folders (-Directory) named "run" (-Filter) here and in all subfolders (-Recurse)
    $runDirs = Get-ChildItem -Path . -Directory -Recurse -Filter "run"
    
    # foreach: Loops through each "run" folder found, one at a time
    foreach ($dir in $runDirs) {
        
        # Split-Path: Gets the path of the parent folder (the folder that contains this specific "run" folder)
        $parent = Split-Path $dir.FullName -Parent
        
        # Test-Path: Checks if "build.gradle" exists in that parent folder to confirm it is a Minecraft mod
        if (Test-Path "$parent\build.gradle") {
            
            # Remove-Item: Deletes the "run" folder and everything inside it (-Recurse) without asking (-Force)
            Remove-Item -Path $dir.FullName -Recurse -Force
        }
    }
}

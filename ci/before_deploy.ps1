# This script takes care of packaging the build artifacts that will go in the
# release zipfile

# Create target folder to put files in.
$TARGET_DIR = ".\deployment\$($Env:FRIENDLY_TARGET_NAME)"
New-Item -Type Directory -Path $TARGET_DIR

# Copy the binary file. This is the only actual file we're packaging.
Copy-Item ".\target\$($Env:TARGET)\release\$($Env:PROJECT_NAME).exe" "$TARGET_DIR\"

Push-Location "$TARGET_DIR"

# Create a basic SHASUM file
(Get-ChildItem -File "." |
        Get-FileHash -Algorithm SHA256 |
        Format-Table -Property @{Name='Path';Expression={Resolve-Path -Relative $_.Path}},Hash -AutoSize -HideTableHeaders |
        Out-String).Trim() | Out-File -Path "./SHA256SUM"

Pop-Location
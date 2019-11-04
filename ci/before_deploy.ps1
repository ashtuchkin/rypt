# This script takes care of packaging the build artifacts that will go in the
# release zipfile

$SRC_DIR = $PWD.Path
New-Item -Type Directory -Name deployment

Set-Location $ENV:Temp
$STAGE = [System.Guid]::NewGuid().ToString()
New-Item -Type Directory -Name $STAGE
Set-Location $STAGE

$ZIP = "$SRC_DIR\deployment\$($Env:PROJECT_NAME)-$($Env:APPVEYOR_REPO_TAG_NAME)-$($Env:FRIENDLY_TARGET_NAME).zip"

# TODO Update this to package the right artifacts
Copy-Item "$SRC_DIR\target\$($Env:TARGET)\release\$($Env:PROJECT_NAME).exe" '.\'
Copy-Item "$SRC_DIR\README.md" '.\'
Copy-Item "$SRC_DIR\LICENSE" '.\'

7z a "$ZIP" *

Push-AppveyorArtifact "$ZIP"

Remove-Item *.* -Force
Set-Location $SRC_DIR

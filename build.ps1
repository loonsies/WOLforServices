# PowerShell script to run the build container and package the plugin
$ErrorActionPreference = "Stop"

Write-Host "=== Building WOL4Services Docker Image ===" -ForegroundColor Green
docker build -t wol4services-builder .

Write-Host "=== Running build inside Docker ===" -ForegroundColor Green
docker run --rm -v "${PWD}:/workspace" wol4services-builder bash -c "chmod +x /workspace/build-package.sh && /workspace/build-package.sh"

Write-Host "=== Build and package completed! ===" -ForegroundColor Green

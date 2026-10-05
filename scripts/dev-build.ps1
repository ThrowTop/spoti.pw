# Commit code first. This pushes the selected branch, waits for its source build, and patches locally.
[CmdletBinding()]
param(
    [string]$Ipa = $(if ($env:SPOTI_IPA) { $env:SPOTI_IPA } else { Join-Path $env:USERPROFILE 'Downloads/com.spotify.client-9.1.78.ipa' }),
    [string]$Ref = 'codex/fast-kit-builds',
    [switch]$Bootstrap,
    [switch]$Clean,
    [switch]$NoWait,
    [string]$Kit
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
Push-Location $repoRoot
try {
    if ($Bootstrap -and $NoWait) { throw '-Bootstrap must wait so it can delete the temporary IPA upload.' }
    $nodeVersion = node --version
    if ($LASTEXITCODE -ne 0 -or [int]($nodeVersion.TrimStart('v').Split('.')[0]) -lt 24) { throw 'Install Node 24 or newer before building.' }
    $ipaPath = (Resolve-Path -LiteralPath $Ipa).Path
    if (-not $Kit) {
        if ((git branch --show-current) -ne $Ref) { throw "Check out $Ref before building, or pass -Ref with your current branch." }
        if (git status --porcelain) { throw 'Commit your changes before building so the downloaded kit identifies the exact source.' }
        $sourceCommit = git rev-parse HEAD
        $repoName = gh repo view --json nameWithOwner --jq .nameWithOwner
        if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve GitHub repository.' }
        if ($Bootstrap) {
            $baseHash = (Get-FileHash -LiteralPath $ipaPath -Algorithm SHA256).Hash.ToLowerInvariant()
            gh variable set KIT_BASE_SHA256 --body $baseHash
            if ($LASTEXITCODE -ne 0) { throw 'Could not set base IPA fingerprint.' }
            $binName = 'spoti-kit-' + [guid]::NewGuid().ToString('N')
            $uploadUrl = "https://filebin.net/$binName/base.ipa"
            curl.exe -fsS --retry 2 -X POST -H 'Content-Type: application/octet-stream' --data-binary "@$ipaPath" $uploadUrl -o NUL
            if ($LASTEXITCODE -ne 0) { throw 'Bootstrap upload failed.' }
            $uploadUrl | gh secret set KIT_BOOTSTRAP_IPA_URL
            if ($LASTEXITCODE -ne 0) { throw 'Could not set bootstrap URL secret.' }
            New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'out') | Out-Null
            @{ url = $uploadUrl } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $repoRoot 'out/bootstrap-upload.json')
            Write-Host 'Bootstrap IPA uploaded; only derived inputs are retained by Actions.'
        }
        git push -u origin $Ref
        if ($LASTEXITCODE -ne 0) { throw 'Push failed.' }
        $run = $null
        for ($attempt = 0; $attempt -lt 12; $attempt++) {
            $runs = @(gh run list --branch $Ref --commit $sourceCommit --limit 20 --json databaseId,status,conclusion,url,workflowName | ConvertFrom-Json) | Where-Object { $_.workflowName -eq 'Build custom kit' }
            if ($LASTEXITCODE -eq 0 -and $runs.Count -gt 0) { $run = @($runs)[0]; break }
            Start-Sleep -Seconds 3
        }
        if (-not $run -or $Clean -or ($run.status -eq 'completed' -and $run.conclusion -ne 'success')) {
            $workflowId = gh api "repos/$repoName/actions/workflows" --jq '.workflows[] | select(.name == "Build custom kit") | .id'
            if (-not $workflowId) { throw 'Push a source commit to register the new workflow, then run this command again.' }
            gh workflow run $workflowId --ref $Ref -f "clean=$($Clean.IsPresent.ToString().ToLowerInvariant())"
            if ($LASTEXITCODE -ne 0) { throw 'Dispatch failed. Push a source commit to trigger the workflow, then run this command again.' }
            Start-Sleep -Seconds 3
            $runs = @(gh run list --branch $Ref --commit $sourceCommit --limit 20 --json databaseId,status,conclusion,url,workflowName | ConvertFrom-Json) | Where-Object { $_.workflowName -eq 'Build custom kit' }
            $run = @($runs)[0]
        }
        Write-Host "Build: $($run.url)"
        if ($NoWait) { return }
        gh run watch $run.databaseId --exit-status
        if ($LASTEXITCODE -ne 0) { throw 'Kit build failed; inspect the linked Actions run.' }
        $downloadDir = Join-Path $repoRoot "out/kits/$($run.databaseId)"
        New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null
        gh run download $run.databaseId --name custom-kit --dir $downloadDir
        if ($LASTEXITCODE -ne 0) { throw 'Kit download failed.' }
        $Kit = (Get-ChildItem -LiteralPath $downloadDir -Filter '*-kit.zip' | Select-Object -First 1).FullName
    }
    node (Join-Path $PSScriptRoot 'patcher.mjs') $ipaPath (Resolve-Path -LiteralPath $Kit).Path (Join-Path $repoRoot 'out')
    if ($LASTEXITCODE -ne 0) { throw 'Local patch failed.' }
    $bootstrapRecord = Join-Path $repoRoot 'out/bootstrap-upload.json'
    if (Test-Path -LiteralPath $bootstrapRecord) {
        $previousUpload = Get-Content -LiteralPath $bootstrapRecord -Raw | ConvertFrom-Json
        curl.exe -fsS -X DELETE $previousUpload.url -o NUL
        if ($LASTEXITCODE -ne 0) { throw 'The IPA was built, but Filebin cleanup failed. Run the command again to retry cleanup.' }
        gh secret delete KIT_BOOTSTRAP_IPA_URL
        if ($LASTEXITCODE -ne 0) { throw 'The IPA was built, but the bootstrap secret could not be deleted.' }
        Remove-Item -LiteralPath $bootstrapRecord
    }
} finally {
    Pop-Location
}

param(
  [switch]$SkipElectronBuilder
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Step {
  param([string]$Message)
  Write-Host ''
  Write-Host "==> $Message" -ForegroundColor Cyan
}

function Ensure-FileExists {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "Required file not found: $Path"
  }
}

function Ensure-Directory {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
  }
}

function Clear-Directory {
  param([string]$Path)
  Ensure-Directory -Path $Path
  Get-ChildItem -LiteralPath $Path -Force | Remove-Item -Recurse -Force
}

function Invoke-Checked {
  param(
    [string]$FilePath,
    [string[]]$Arguments,
    [string]$WorkingDirectory = $repoRoot
  )

  Push-Location $WorkingDirectory
  try {
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
      throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
  }
  finally {
    Pop-Location
  }
}

function Write-AsciiFile {
  param(
    [string]$Path,
    [string]$Content
  )

  [System.IO.File]::WriteAllText($Path, $Content, [System.Text.Encoding]::ASCII)
}

function Invoke-BytenodeCompile {
  param(
    [string]$InputFile,
    [string]$OutputFile
  )

  $compileScript = @'
const bytenode = require('bytenode');
const [inputFile, outputFile] = process.argv.slice(1);
(async () => {
  await bytenode.compileFile({ filename: inputFile, output: outputFile });
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
'@

  Invoke-Checked -FilePath 'node' -Arguments @('-e', $compileScript, $InputFile, $OutputFile)
}

Push-Location $repoRoot
try {
  $rootEsbuild = Join-Path $repoRoot 'node_modules\.bin\esbuild.cmd'
  $rootObfuscator = Join-Path $repoRoot 'node_modules\.bin\javascript-obfuscator.cmd'
  $electronBuilder = Join-Path $repoRoot 'electron-app\node_modules\.bin\electron-builder.cmd'

  Ensure-FileExists -Path $rootEsbuild
  Ensure-FileExists -Path $rootObfuscator
  if (-not $SkipElectronBuilder) {
    Ensure-FileExists -Path $electronBuilder
  }

  $rootBuildArtifacts = Join-Path $repoRoot 'build-artifacts'
  $agentDistDir = Join-Path $repoRoot 'dist\agent'
  $electronBuildArtifacts = Join-Path $repoRoot 'electron-app\build-artifacts'
  $electronRuntimeDir = Join-Path $repoRoot 'electron-app\runtime\electron'

  Write-Step 'Preparing output folders'
  Clear-Directory -Path $rootBuildArtifacts
  Clear-Directory -Path $agentDistDir
  Clear-Directory -Path $electronBuildArtifacts
  Clear-Directory -Path $electronRuntimeDir

  $agentEntry = Join-Path $repoRoot 'agent\dsc-agent.js'
  $agentBundle = Join-Path $rootBuildArtifacts 'dsc-agent.bundle.js'
  $agentObf = Join-Path $rootBuildArtifacts 'dsc-agent.obf.js'
  $agentJsc = Join-Path $agentDistDir 'dsc-agent.jsc'
  $agentLoader = Join-Path $agentDistDir 'dsc-agent.loader.js'

  Write-Step 'Bundling agent'
  Invoke-Checked -FilePath $rootEsbuild -Arguments @(
    $agentEntry,
    '--bundle',
    '--platform=node',
    '--format=cjs',
    '--target=node18',
    '--external:pkcs11js',
    "--outfile=$agentBundle"
  )

  Write-Step 'Obfuscating agent bundle'
  Invoke-Checked -FilePath $rootObfuscator -Arguments @(
    $agentBundle,
    '--output', $agentObf,
    '--target', 'node',
    '--compact', 'true',
    '--identifier-names-generator', 'hexadecimal',
    '--rename-globals', 'false',
    '--simplify', 'true',
    '--string-array', 'true',
    '--string-array-encoding', 'base64',
    '--string-array-threshold', '0.75',
    '--unicode-escape-sequence', 'false'
  )

  Write-Step 'Compiling agent bytecode'
  Invoke-BytenodeCompile -InputFile $agentObf -OutputFile $agentJsc
  Write-AsciiFile -Path $agentLoader -Content "require('bytenode');`nrequire('./dsc-agent.jsc');`n"

  $electronMainSource = Join-Path $repoRoot 'electron-app\main-bytecode-point.js'
  $electronPinSource = Join-Path $repoRoot 'electron-app\main\pinPromptServer.js'
  $electronPreloadSource = Join-Path $repoRoot 'electron-app\preload.js'

  $electronMainBundle = Join-Path $electronBuildArtifacts 'main.bundle.js'
  $electronMainObf = Join-Path $electronBuildArtifacts 'main.obf.js'
  $electronPinBundle = Join-Path $electronBuildArtifacts 'pinPromptServer.bundle.js'
  $electronPinObf = Join-Path $electronBuildArtifacts 'pinPromptServer.obf.js'
  $electronPreloadBundle = Join-Path $electronBuildArtifacts 'preload.bundle.js'
  $electronPreloadObf = Join-Path $electronBuildArtifacts 'preload.obf.js'

  $stagedPinSource = Join-Path $electronBuildArtifacts 'pinPromptServer.bytecode-point.js'

  Write-Step 'Staging bytecode-safe Electron sources'
  $pinSourceText = Get-Content -LiteralPath $electronPinSource -Raw
  $pinSourceText = $pinSourceText.Replace(
    "require('path').join(__dirname, '..', 'renderer', 'pin.html')",
    "require('path').join(__dirname, '..', '..', 'renderer', 'pin.html')"
  )
  Write-AsciiFile -Path $stagedPinSource -Content $pinSourceText

  Write-Step 'Bundling Electron main process'
  Invoke-Checked -FilePath $rootEsbuild -Arguments @(
    $electronMainSource,
    '--bundle',
    '--platform=node',
    '--format=cjs',
    '--target=node18',
    '--external:electron',
    '--external:./pinPromptServer.loader.js',
    "--outfile=$electronMainBundle"
  )

  Write-Step 'Bundling Electron PIN prompt server'
  Invoke-Checked -FilePath $rootEsbuild -Arguments @(
    $stagedPinSource,
    '--bundle',
    '--platform=node',
    '--format=cjs',
    '--target=node18',
    '--external:electron',
    "--outfile=$electronPinBundle"
  )

  Write-Step 'Bundling Electron preload'
  Invoke-Checked -FilePath $rootEsbuild -Arguments @(
    $electronPreloadSource,
    '--bundle',
    '--platform=node',
    '--format=cjs',
    '--target=node18',
    '--external:electron',
    "--outfile=$electronPreloadBundle"
  )

  Write-Step 'Obfuscating Electron runtime files'
  foreach ($pair in @(
    @{ Input = $electronMainBundle; Output = $electronMainObf },
    @{ Input = $electronPinBundle; Output = $electronPinObf },
    @{ Input = $electronPreloadBundle; Output = $electronPreloadObf }
  )) {
    Invoke-Checked -FilePath $rootObfuscator -Arguments @(
      $pair.Input,
      '--output', $pair.Output,
      '--target', 'node',
      '--compact', 'true',
      '--identifier-names-generator', 'hexadecimal',
      '--rename-globals', 'false',
      '--simplify', 'true',
      '--string-array', 'true',
      '--string-array-encoding', 'base64',
      '--string-array-threshold', '0.75',
      '--unicode-escape-sequence', 'false'
    )
  }

  Write-Step 'Compiling Electron main and PIN prompt bytecode'
  Invoke-BytenodeCompile -InputFile $electronMainObf -OutputFile (Join-Path $electronRuntimeDir 'main.jsc')
  Invoke-BytenodeCompile -InputFile $electronPinObf -OutputFile (Join-Path $electronRuntimeDir 'pinPromptServer.jsc')

  Write-Step 'Publishing Electron runtime loaders'
  Write-AsciiFile -Path (Join-Path $electronRuntimeDir 'main.loader.js') -Content "require('bytenode');`nrequire('./main.jsc');`n"
  Write-AsciiFile -Path (Join-Path $electronRuntimeDir 'pinPromptServer.loader.js') -Content "require('bytenode');`nmodule.exports = require('./pinPromptServer.jsc');`n"
  Copy-Item -LiteralPath $electronPreloadObf -Destination (Join-Path $electronRuntimeDir 'preload.obf.js') -Force

  $electronPackage = Join-Path $repoRoot 'electron-app\package.json'
  $electronPackageProtected = Join-Path $repoRoot 'electron-app\package.json-bytecode-point'
  $electronPackageBackup = Join-Path $repoRoot 'electron-app\package.json.build-protected.bak'

  if (-not $SkipElectronBuilder) {
    Write-Step 'Building protected Electron app'
    Copy-Item -LiteralPath $electronPackage -Destination $electronPackageBackup -Force
    try {
      Copy-Item -LiteralPath $electronPackageProtected -Destination $electronPackage -Force
      Invoke-Checked -FilePath $electronBuilder -Arguments @('--win') -WorkingDirectory (Join-Path $repoRoot 'electron-app')
    }
    finally {
      if (Test-Path -LiteralPath $electronPackageBackup) {
        Move-Item -LiteralPath $electronPackageBackup -Destination $electronPackage -Force
      }
    }
  }

  Write-Step 'Protected build completed'
  Write-Host "Agent loader: $agentLoader"
  Write-Host "Electron runtime: $electronRuntimeDir"
  if ($SkipElectronBuilder) {
    Write-Host 'Electron Builder was skipped.'
  }
  else {
    Write-Host "Installer output: $(Join-Path $repoRoot 'electron-app\dist')"
  }
}
finally {
  Pop-Location
}

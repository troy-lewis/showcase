# PowerShell script to install the PSFalcon module from the PowerShell Gallery
# Troy Lewis
# Version 1.0

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Clear-Host

Write-Host "Checking for Admin privileges..." -ForegroundColor Cyan
$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as an Administrator."
    exit 1
}

$currentExectionPolicy = Get-ExecutionPolicy -Scope LocalMachine
if ($currentExectionPolicy -ne 'RemoteSigned') {
    Write-Host "Setting Execution Policy to RemoteSigned..." -ForegroundColor Cyan
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
}

$moduleToInstall = 'PSFalcon'
if (Get-Module -ListAvailable -Name $moduleToInstall) {
    Write-Host "$moduleToInstall is already installed." -ForegroundColor Green
} else {
    Write-Host "Installing $moduleToInstall from the PowerShell Gallery..." -ForegroundColor Cyan
    try {
        Install-Module -Name $moduleToInstall -Scope AllUsers -Force -AllowClobber
        Write-Host "$moduleToInstall installed successfully." -ForegroundColor Green
    } catch {
        Write-Error "Failed to install $moduleToInstall $_"
        exit 1
    }
}

Write-Host "Importing $moduleToInstall..." -ForegroundColor Cyan
try {
    Import-Module -Name $moduleToInstall -Force
    Write-Host "$moduleToInstall imported successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to import $moduleToInstall $_"
    exit 1
}

Write-Host "PSFalcon module installation and import completed successfully." -ForegroundColor Green
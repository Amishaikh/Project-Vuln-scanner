# ==========================================
# Python Setup + Run Script
# ==========================================

function Check-Internet {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect("8.8.8.8", 53, $null, $null)
        $success = $iar.AsyncWaitHandle.WaitOne(3000, $false)
        $client.Close()
        return $success
    }
    catch {
        return $false
    }
}

function Test-PythonInstalled {
    try {
        Get-Command python -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Install-Python {
    try {
        Write-Host "Python is not installed."
        Write-Host "Downloading and installing Python..."
        Write-Host ""

        $pythonUrl = "https://www.python.org/ftp/python/3.12.1/python-3.12.1-amd64.exe"
        $installerPath = Join-Path $env:TEMP "python_installer.exe"

        Invoke-WebRequest -Uri $pythonUrl -OutFile $installerPath

        Start-Process -FilePath $installerPath -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1" -Wait

        Start-Sleep -Seconds 5

        Write-Host "Python has been installed successfully."
        Write-Host ""
    }
    catch {
        Write-Host "An error occurred during installation."
        Write-Host "Please try again or contact your system administrator."
        exit
    }
}

function Run-PythonScript {
    try {
        $currentDir = (Get-Location).Path
        $scriptPath = Join-Path $currentDir "main.py"
        $pythonExe = "C:\Users\amisa\AppData\Local\Programs\Python\Python314\python.exe"

        if (!(Test-Path $scriptPath)) {
            Write-Host "[!] main.py not found in current folder."
            return
        }

        if (!(Test-Path $pythonExe)) {
            Write-Host "[!] Python executable not found."
            return
        }

        Write-Host "[*] Starting vulnerability scan with administrator privileges..."

        $argString = "-NoExit -ExecutionPolicy Bypass -Command `"Set-Location -Path '$currentDir'; & '$pythonExe' '$scriptPath'`""

        Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argString
    }
    catch {
        Write-Host "[!] Error: $($_.Exception.Message)"
    }
}

# =========================
# MAIN
# =========================

Write-Host ""
Write-Host "Checking internet connection..."
Write-Host ""

if (-not (Check-Internet)) {
    Write-Host "No internet connection detected."
    Write-Host ""
    Write-Host "Please connect to the internet and run this script again."
    Write-Host "An active internet connection is required for setup."
    Write-Host ""
    exit
}

Write-Host "Internet connection detected."
Write-Host ""

if (Test-PythonInstalled) {
    Write-Host "Python is already installed."
} else {
    Install-Python
}

# ✅ Always run script after check/install
Run-PythonScript

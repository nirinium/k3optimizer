#Variables, only Change here
$Destination = "X:\NTG\IT\Programming\bkups" #Copy the Files to this Location
$Versions = "2" #How many of the last Backups you want to keep
$BackupDirs = "X:\NTG\IT\Programming\Scripts" #,"Z:\" #What Folders you want to backup
$ExcludeDirs = "C:\Program Files (x86)\OpenVPN\bin", "C:\Program Files (x86)\OpenVPN\config" #This list of Directories will not be copied
$LogName = "log.txt" #Log Name
$LoggingLevel = "3" #LoggingLevel only for Output in Powershell Window, 1=smart, 3=Heavy
$Zip = $true #Zip the Backup Destination
$RemoveBackupDestination = $false #Remove copied files after Zip, only if $Zip is true


#Send Mail Settings
$SendEmail = $true                    # = $true if you want to enable send report to e-mail (SMTP send)

#STOP-no changes from here
#STOP-no changes from here
#Settings - do not change anything from here
$Backupdir = $Destination + "\Backup-" + (Get-Date -format yyyy-MM-dd) + "-" + (Get-Random -Maximum 100000) + "\"
$Log = $Backupdir + $LogName
$Items = 0
$Count = 0
$ErrorCount = 0
$StartDate = Get-Date

#FUNCTION
#Logging
Function Logging ($State, $Message) {
    $Datum = Get-Date -format dd.MM.yyyy-HH:mm:ss

    if (!(Test-Path -Path $Log)) {
        New-Item -Path $Log -ItemType File | Out-Null
    }
    $Text = "$Datum - $State" + ":" + " $Message"

    if ($LoggingLevel -eq "1" -and $Message -notmatch "was copied") {Write-Host $Text}
    elseif ($LoggingLevel -eq "3") {Write-Host $Text}
   
    add-Content -Path $Log -Value $Text
    Start-Sleep -Milliseconds 100
}


#Create Backupdir
Function Create-Backupdir {
    New-Item -Path $Backupdir -ItemType Directory | Out-Null
    Start-Sleep -Seconds 3
    Logging "INFO" "Create BackupDir $Backupdir"
}

#Delete Backupdir
Function Delete-Backupdir {
    $Folder = Get-ChildItem $Destination | Where-Object {$_.Attributes -eq "Directory"} | Sort-Object -Property $_.CreationTime  -Descending:$true | Select-Object -First 1

    Logging "INFO" "Remove Dir: $Folder"
    
    $Folder.FullName | Remove-Item -Recurse -Force 
}


#Delete Zip
Function Delete-Zip {
    $Zip = Get-ChildItem $Destination | where {$_.Attributes -eq "Archive" -and $_.Extension -eq ".zip"} | Sort-Object -Property $_.CreationTime  -Descending:$true | Select-Object -First 1

    Logging "INFO" "Remove Zip: $Zip"
    
    $Zip.FullName | Remove-Item -Recurse -Force 
}

#Check if Backupdirs and Destination is available
function Check-Dir {
    Logging "INFO" "Check if BackupDir and Destination exists"
    if (!(Test-Path $BackupDirs)) {
        return $false
        Logging "Error" "$BackupDirs does not exist"
    }
    if (!(Test-Path $Destination)) {
        return $false
        Logging "Error" "$Destination does not exist"
    }
}

#Save all the Files
Function Make-Backup {
    Logging "INFO" "Started the Backup"
    $Files = @()
    $SumMB = 0
    $SumItems = 0
    $SumCount = 0
    $colItems = 0
    Logging "INFO" "Count all files and create the Top Level Directories"

    foreach ($Backup in $BackupDirs) {
        $colItems = (Get-ChildItem $Backup -recurse | Where-Object {$_.mode -notmatch "h"} | Measure-Object -property length -sum) 
        $Items = 0
        $FilesCount += Get-ChildItem $Backup -Recurse | Where-Object {$_.mode -notmatch "h"}  
        Copy-Item -Path $Backup -Destination $Backupdir -Force -ErrorAction SilentlyContinue
        $SumMB += $colItems.Sum.ToString()
        $SumItems += $colItems.Count
    }

    $TotalMB = "{0:N2}" -f ($SumMB / 1MB) + " MB of Files"
    Logging "INFO" "There are $SumItems Files with  $TotalMB to copy"

    foreach ($Backup in $BackupDirs) {
        $Index = $Backup.LastIndexOf("\")
        $SplitBackup = $Backup.substring(0, $Index)
        $Files = Get-ChildItem $Backup -Recurse | Where-Object {$_.mode -notmatch "h" -and $ExcludeDirs -notcontains $_.FullName} 
        foreach ($File in $Files) {
            $restpath = $file.fullname.replace($SplitBackup, "")
            try {
                Copy-Item  $file.fullname $($Backupdir + $restpath) -Force -ErrorAction SilentlyContinue |Out-Null
                Logging "INFO" "$file was copied"
            }
            catch {
                $ErrorCount++
                Logging "ERROR" "$file returned an error an was not copied"
            }
            $Items += (Get-item $file.fullname).Length
            $status = "Copy file {0} of {1} and copied {3} MB of {4} MB: {2}" -f $count, $SumItems, $file.Name, ("{0:N2}" -f ($Items / 1MB)).ToString(), ("{0:N2}" -f ($SumMB / 1MB)).ToString()
            $Index = [array]::IndexOf($BackupDirs, $Backup) + 1
            $Text = "Copy data Location {0} of {1}" -f $Index , $BackupDirs.Count
            Write-Progress -Activity $Text $status -PercentComplete ($Items / $SumMB * 100)  
            if ($File.Attributes -ne "Directory") {$count++}
        }
    }
    $SumCount += $Count
    $SumTotalMB = "{0:N2}" -f ($Items / 1MB) + " MB of Files"
    Logging "INFO" "----------------------"
    Logging "INFO" "Copied $SumCount files with $SumTotalMB"
    Logging "INFO" "$ErrorCount Files could not be copied"


    # Send e-mail with reports as attachments
    if ($SendEmail -eq $true) {

        # Import the credential from the file later
        $cred = Import-CliXml  X:\Backups\GmailCredential.xml

        # Send the mail message (use -BodyAsHtml instead of -Body if you have an HTML body)
        $sendMailArguments = @{
            SmtpServer = "smtp.gmail.com"
            Credential = $cred
            UseSsl     = $true
            Port       = 587
            To         = "wills.colton@gmail.com"
            From       = "wills.colton@gmail.com"
            Subject    = "Backup Report $(get-date -format MM.dd.yyyy)"
            Body       =  Get-Content $Log | Out-String
            attachments = $Log 
        }
        Send-MailMessage @sendMailArguments
    }
    Logging "INFO" "Logfile has been sent by email."
}


#Bcreate Backup Dir
Create-Backupdir
Logging "INFO" "--------------------------------------------------------------------"
Logging "INFO" "Performing environment check..."

#Check if Backupdir needs to be cleaned and create Backupdir
$Count = (Get-ChildItem $Destination | where {$_.Attributes -eq "Directory"}).count
Logging "INFO" "Check if there are more than $Versions Directories in the Backupdir"

if ($count -gt $Versions) {

    Delete-Backupdir

}


$CountZip = (Get-ChildItem $Destination | where {$_.Attributes -eq "Archive" -and $_.Extension -eq ".zip"}).count
Logging "INFO" "Check if there are more than $Versions Zip in the Backupdir"

if ($CountZip -gt $Versions) {

    Delete-Zip 

}

#Check if all Dir are existing and do the Backup
$CheckDir = Check-Dir

if ($CheckDir -eq $false) {
    Logging "ERROR" "A directory is not available, stopping script."
}
else {
    Make-Backup

    $Enddate = Get-Date #-format dd.MM.yyyy-HH:mm:ss
    $span = $EndDate - $StartDate
    $Minutes = $span.Minutes
    $Seconds = $Span.Seconds

    Logging "INFO" "Backup Duration $Minutes Minutes and $Seconds Seconds"
    Logging "INFO" "----------------------"

    if ($Zip) {
        Logging "INFO" "Zipping Backup Destination..."
        Compress-Archive -Path $Backupdir -DestinationPath ($Destination + ("\" + $Backupdir.Replace($Destination, '').Replace('\', '') + ".zip")) -CompressionLevel Optimal -Force

        If ($RemoveBackupDestination) {
            Logging "INFO" "Elapsed: $Minutes Minutes and $Seconds Seconds"

            #Remove-Item -Path $BackupDir -Force -Recurse 
            get-childitem -Path $BackupDir -recurse -Force  | remove-item -Confirm:$false -Recurse
            get-item -Path $BackupDir   | remove-item -Confirm:$false -Recurse
        }
        Logging "INFO" "Backup Complete."
    }
}

Exit-PSSession
#Write-Host "Press any key to close ..."

#$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")




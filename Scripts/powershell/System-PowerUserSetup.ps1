###############################


#Download and install VC++ redistrib

#Enable long paths

#Trim Drives / Optimize

# SET ULTIMATE PERFORMANCE POWER PLAN
#powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61

powercfg.exe -hibernate off #Disable Hibernate

powercfg.exe -list

#powercfg.exe -SETACTIVE e9a42b02-d5df-448d-aa00-03f14749eb61

# Disable adding '- shortcut' to shortcut name
Function DisableShortcutInName {
	Write-Output "Disabling adding '- shortcut' to shortcut name..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value ([byte[]](0,0,0,0))
}

# Enable adding '- shortcut' to shortcut name
Function EnableShortcutInName {
	Write-Output "Enabling adding '- shortcut' to shortcut name..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -ErrorAction SilentlyContinue
}

# Show full directory path in Explorer title bar
Function ShowExplorerTitleFullPath {
	Write-Output "Showing full directory path in Explorer title bar..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name "FullPath" -Type DWord -Value 1
}

# Hide full directory path in Explorer title bar, only directory name will be shown
Function HideExplorerTitleFullPath {
	Write-Output "Hiding full directory path in Explorer title bar..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name "FullPath" -ErrorAction SilentlyContinue
}


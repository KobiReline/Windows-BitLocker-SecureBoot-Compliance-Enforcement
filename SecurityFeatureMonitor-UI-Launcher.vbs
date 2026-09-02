Option Explicit

Dim fileSystem
Dim installDirectory
Dim powerShellScript
Dim command
Dim shell
Dim exitCode

Set fileSystem = CreateObject("Scripting.FileSystemObject")
installDirectory = fileSystem.GetParentFolderName(WScript.ScriptFullName)
powerShellScript = fileSystem.BuildPath(installDirectory, "SecurityFeatureMonitor-UI.ps1")
command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File """ & powerShellScript & """"

Set shell = CreateObject("WScript.Shell")
exitCode = shell.Run(command, 0, True)
WScript.Quit exitCode

Option Explicit

Dim fileSystem
Dim installDirectory
Dim powerShellScript
Dim powerShellExecutable
Dim command
Dim shell
Dim exitCode

Set fileSystem = CreateObject("Scripting.FileSystemObject")
installDirectory = fileSystem.GetParentFolderName(WScript.ScriptFullName)
powerShellScript = fileSystem.BuildPath(installDirectory, "SecurityFeatureMonitor-UI.ps1")
Set shell = CreateObject("WScript.Shell")
powerShellExecutable = shell.ExpandEnvironmentStrings("%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe")
command = """" & powerShellExecutable & """ -NoProfile -STA -ExecutionPolicy Bypass -File """ & powerShellScript & """"
exitCode = shell.Run(command, 0, True)
WScript.Quit exitCode

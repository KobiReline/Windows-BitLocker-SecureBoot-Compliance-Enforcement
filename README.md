# Windows BitLocker Secure Boot Compliance Enforcement

The solution uses two security contexts:

- `NT AUTHORITY\SYSTEM`: installation, compliance checks, downloads, protected state and scheduled-task management.
- Logged-on user (`RunLevel Limited`): alert UI, window minimization, volume control and hidden audio playback only.

No Win32 app packaging or code-signing certificate is required by the current version. Scripts run locally with `ExecutionPolicy Bypass`. The installed directory is writable only by Administrators and SYSTEM. Signing or pinning script hashes is recommended before broad production use.

## Intune Remediations deployment

Create one Intune Remediations package and upload:

- Detection script: `Detect-SecurityFeatureMonitor.ps1`
- Remediation script: `Deploy-FromIntune.ps1`

Configure:

- Run this script using the logged-on credentials: **No**
- Enforce script signature check: **No**
- Run script in 64-bit PowerShell host: **Yes**

- Schedule: **Daily**

The detection script checks the installed version, every installed file SHA-256, both media assets, and the backend/UI scheduled-task definitions. It writes compact JSON to Intune as the pre-remediation or post-remediation detection output.

The remediation script downloads `manifest.json`, validates every downloaded file against the manifest, installs the files under `C:\ProgramData\SecurityFeatureMonitor`, recreates both scheduled tasks and runs an immediate backend check. The backend runs as SYSTEM and writes state only. The UI task is then triggered in the logged-on user's context.

After self-healing, a noncompliant device displays one immediate UI alert without audio. A later regular critical-state backend run restores normal audio behavior.

The backend task runs as SYSTEM at startup and hourly. The UI task runs for logged-on users at logon and every five minutes. State and media are stored under `C:\Windows\Logs\SecurityCheck`.

## Important behavior

Media files are checked during the first backend run and every later run. A missing file or a file whose SHA-256 is wrong is downloaded again. A valid file is not downloaded again. If the device is offline and no valid audio file exists, the visual alert still works.

`manifest.json` is the update contract. To publish a new version, change the scripts, update their SHA-256 values in the manifest, and increment `Version`. The next daily Intune detection reports `VersionMismatch` or `HashMismatch`; remediation then installs the new version.

Intune retains the latest per-device pre-remediation output, post-remediation output, execution time and run states. It does not provide a complete immutable per-device history of every old output. The JSON schema is intentionally stable so a future central Microsoft Graph collector can archive results without changing the endpoint scripts.

## Test mode

Test mode ignores the device's real BitLocker and Secure Boot state. Run the installed helper elevated, or deploy it temporarily from Intune as SYSTEM.

```powershell
# Simulate the warning-period alert; repeat after one minute.
& 'C:\ProgramData\SecurityFeatureMonitor\Set-SecurityFeatureMonitorTestMode.ps1' -Scenario Warning -AlertIntervalMinutes 1

# Simulate the critical alert, including volume and both audio files.
& 'C:\ProgramData\SecurityFeatureMonitor\Set-SecurityFeatureMonitorTestMode.ps1' -Scenario Critical -AlertIntervalMinutes 1

# Return to real production checks.
& 'C:\ProgramData\SecurityFeatureMonitor\Set-SecurityFeatureMonitorTestMode.ps1' -Disable
```

Available scenarios are `Healthy`, `Grace`, `Warning`, and `Critical`. Every test state includes `IsTestMode: true` in `State.json`. Disabling test mode triggers the tasks again and restores checks against the real device state.

For a one-time UI-only test from the logged-on user's session:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\ProgramData\SecurityFeatureMonitor\SecurityFeatureMonitor-UI.ps1' -ForceDisplay -ForceAudio
```

Both audio files are opened and prepared before the dialog is displayed. Playback is invisible, starts with the dialog, plays `bip.wav` twice followed by `alarm.mp3` three times, and releases all media resources when the sequence finishes—even if the dialog is still open. If the dialog is closed first, the hidden playback process remains only until the sequence finishes and then exits.

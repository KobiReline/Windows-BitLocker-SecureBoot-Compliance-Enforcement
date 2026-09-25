# Windows BitLocker Secure Boot Compliance Enforcement

The solution uses two security contexts:

- `NT AUTHORITY\SYSTEM`: installation, compliance checks, downloads, protected state and scheduled-task management.
- Logged-on user (`RunLevel Limited`): alert UI, window minimization, volume control and hidden audio playback only.

No Win32 app packaging or code-signing certificate is required by the current version. Scripts run locally with `ExecutionPolicy Bypass`. The installed directory is writable only by Administrators and SYSTEM. Signing or pinning script hashes is recommended before broad production use.

## Intune Remediations deployment

Create one Intune Remediations package and upload:

- Detection script: `Intune/Invoke-Detection.ps1`
- Remediation script: `Intune/Invoke-Remediation.ps1`

Upload these two stable entry points once. Do not upload the root-level detection/remediation implementations to Intune. Replace the previous uploads with these entry points when migrating an existing package.

Each invocation (including post-remediation detection) resolves the current `main` commit, downloads its manifest and the selected implementation, verifies SHA-256 and parses it with Windows PowerShell before running it as a child process. The immutable commit URL is passed to the implementation, so its manifest and payload downloads use the same snapshot. Later invocations resolve `main` again; installed backend tasks continue to check `main` for updates.

The entry points forward the child stdout, stderr and numeric exit code. They add no success messages. Detection exit 1 requests remediation; exit 0 means no detected installation issue. A bootstrap download, manifest, hash or syntax failure produces compact `BootstrapFailed` JSON and exit 2, never a healthy result. An uncaught child exception also returns exit 2. Intune limits reported output to 2,048 characters; keep implementation output compact. This does not add history retention beyond Intune's own reporting.

Downloads use a unique temporary directory under `Staging`, writable/readable only by SYSTEM and Administrators, removed after execution. No stale downloaded script is used if fetching the latest snapshot fails. The existing local backend/UI tasks continue to operate offline. Public GitHub access, including `api.github.com` for commit resolution, must work as SYSTEM. GitHub API rate limiting or connectivity failure is reported as a bootstrap error.

The manifest and SHA values are trusted from this repository over HTTPS; hashes validate payload consistency, not an independent code-signing identity. No token, tenant or employee identifier is included.

### Publishing future fixes

1. Update the implementation scripts in GitHub.
2. Recalculate SHA-256 in `manifest.json`: `Files` for every changed payload, plus `EntryPoints.Detection` and/or `EntryPoints.Remediation` if those implementations changed. The remediation entry also appears in `Files`; both hashes must match.
3. Publish code and manifest together in one commit after Windows CI passes. A version-number bump is not required for hash-based updates and requires approval.
4. The next scheduled/on-demand Intune invocation fetches the new implementation. No Intune upload is needed for routine logic fixes. Upload new entry points only if their bootstrap contract, repository location or transport requirements change.

Configure:

- Run this script using the logged-on credentials: **No**
- Enforce script signature check: **No**
- Run script in 64-bit PowerShell host: **Yes**

- Schedule: **Daily**

The detection script checks the installed version, every installed file SHA-256, both media assets, and the backend/UI scheduled-task definitions. It writes compact JSON to Intune as the pre-remediation or post-remediation detection output.

The remediation script downloads `manifest.json`, validates every downloaded file against the manifest, installs the files under `C:\ProgramData\SecurityFeatureMonitor`, recreates both scheduled tasks and runs an immediate backend check. The backend runs as SYSTEM and writes state only. The UI task is then triggered in the logged-on user's context.

After self-healing, a noncompliant device displays one immediate UI alert without audio. A later regular critical-state backend run restores normal audio behavior.

The backend task runs as SYSTEM and changes its own schedule after every check. Healthy or excluded devices run daily; non-compliant devices under 24 hours run hourly; non-compliant devices at 24 hours or later run every five minutes. Every backend schedule also includes an AtLogOn trigger running as SYSTEM. The backend starts the on-demand UI task only after it has written the current state. Every machine-wide component is kept below one root:

- `C:\ProgramData\SecurityFeatureMonitor` - installed scripts, local manifest and version label
- `C:\ProgramData\SecurityFeatureMonitor\State` - generated compliance state and failure timestamp
- `C:\ProgramData\SecurityFeatureMonitor\media` - validated local audio
- `C:\ProgramData\SecurityFeatureMonitor\Staging` - verified Intune remediation downloads

## Important behavior

Media files are checked during the first backend run and every later run. A missing file or a file whose SHA-256 is wrong is downloaded again. A valid file is not downloaded again. If the device is offline and no valid audio file exists, the visual alert still works.

BitLocker `EncryptionInProgress` suspends visual and audio alerts even if Secure Boot is still not compliant. The backend checks encryption progress hourly, preserves the pre-encryption warning level and pauses its elapsed-time clock. When encryption finishes, normal evaluation resumes from the saved warning level. The on-demand UI task uses StopExisting, so a backend run stops the prior UI instance before launching the UI against the newly written state.

`manifest.json` is the update contract. After changing an installed script or media file, update its SHA-256 value in the manifest. The next daily Intune detection reports `HashMismatch`, and remediation installs the changed content. `Version` is a human-readable release label for inventory and troubleshooting; it is recommended for a planned release but is not required to deploy a small fix. Hashes, not the version label, decide whether repair is required.

The backend reads the media hashes from its installed copy of `manifest.json`; media hashes are not duplicated in backend source code.

`Intune/Invoke-Detection.ps1` and `Intune/Invoke-Remediation.ps1` are the stable scripts uploaded to Intune. Root-level `Detect-SecurityFeatureMonitor.ps1` and `Deploy-FromIntune.ps1` contain the updateable implementation; the latter is also installed as `Update-SecurityFeatureMonitor.ps1` for backend self-repair. Routine implementation changes need a matching manifest hash, not another Intune upload.

## Post-deployment tests

`TEST/Invoke-SecurityFeatureMonitorTests.ps1` is a single read-only test runner. Run it in 64-bit Windows PowerShell as Administrator. Green is valid, yellow is informational or needs attention, and red is invalid. The script explains the received and expected value for every check and exits `0` on pass or `1` on failure.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\TEST\Invoke-SecurityFeatureMonitorTests.ps1
```

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

Available scenarios are `Healthy`, `Warning`, and `Critical`. Every test state includes `IsTestMode: true` in `State.json`. Disabling test mode triggers the tasks again and restores checks against the real device state.

For a one-time UI-only test from the logged-on user's session:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\ProgramData\SecurityFeatureMonitor\SecurityFeatureMonitor-UI.ps1' -ForceDisplay -ForceAudio
```

Both audio files are opened and prepared before the dialog is displayed. Playback is invisible, starts with the dialog, plays `bip.wav` twice followed by `alarm.mp3` three times, and releases all media resources when the sequence finishes—even if the dialog is still open. If the dialog is closed first, the hidden playback process remains only until the sequence finishes and then exits.


## Integrity and self-update

Every backend run compares all installed payload hashes with the remote manifest and validates both scheduled tasks. A verified local updater repairs changed files or task definitions. Intune Detection remains the external daily recovery layer when the backend task itself is deleted or disabled. Detection and remediation also reject disabled tasks, altered principals/actions, unexpected UI triggers, and an instance policy other than `StopExisting`. Remediation reports success only after post-install hashes and task definitions pass verification.


## Last remediation result

`RemediationResult.json` is retained after detection reads it. It records the last remediation attempt, including its UTC timestamp, and is overwritten by the next remediation attempt. It is not a run history, and its presence does not prove that remediation ran during the current detection cycle. A file already deleted by an older detection script is recreated only when remediation runs again.

# Windows BitLocker Secure Boot Compliance Enforcement

The solution is split into a privileged backend and a least-privileged interactive UI.

## Files

- `SecurityFeatureMonitor-Backend.ps1`: checks Secure Boot, BitLocker and exclusions; writes `State.json` atomically.
- `SecurityFeatureMonitor-UI.ps1`: runs in the logged-on user's limited token and reads state only.
- `Invoke-SecurityFeatureMonitor.ps1`: downloads a signed backend, verifies its signer and falls back to a trusted local cache while offline.
- `Install-SecurityFeatureMonitor.ps1`: installs the UI and its user-context scheduled task.
- `media/bip.wav`: initial beep played twice.
- `media/alarm.mp3`: alarm played three times after the beep.

## Intune deployment

1. Replace the repository placeholders and signer thumbprint, then sign all scripts with an enterprise code-signing certificate trusted by the devices.
2. Deploy and run `Install-SecurityFeatureMonitor.ps1` elevated once.
3. Run `SecurityFeatureMonitor-Backend.ps1` as the privileged Intune detection/remediation component.
4. Configure 64-bit PowerShell.
5. Use the backend exit code: `0` compliant/excluded, `1` noncompliant.

## Important behavior

- The UI task runs as `BUILTIN\Users` with `RunLevel Limited`, including when the signed-in user is a local administrator.
- The backend never starts an interactive process.
- `State.json` and media assets are writable only by Administrators/SYSTEM and readable by Users.
- Both media assets are validated during the first backend run and every later run.
- A media asset is downloaded only when it is missing or its SHA-256 does not match the expected value.
- A valid existing media asset is never downloaded again.
- If a missing media asset cannot be downloaded while offline, the alert remains fully functional without that sound.
- UI polling is every five minutes, but `AlertIntervalMinutes` in state prevents alerts before their configured interval.
- A task using `BUILTIN\Administrators` can run only for a logged-on member of that group. It is not a reliable unattended replacement for Intune's device context.
- The backend bootstrap verifies the exact trusted Authenticode signer before replacing its cache and falls back to the last trusted copy while offline.
- Direct `Invoke-Expression` of unsigned GitHub content is intentionally not used.

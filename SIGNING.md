# KRzr — Driver Signing & Test-Signing Setup

`KernelFuzzer.sys` is unsigned out of the build. Windows refuses to load
unsigned kernel drivers on production kernels, so the driver must be
either (a) loaded on a system with **test-signing** enabled and signed
with a test certificate, or (b) signed by an EV certificate chained to
the Microsoft cross-signing CA. KRzr is a research artefact intended
for dedicated kernel-debug VMs — path (a) is the supported flow.

This document is the missing piece referenced from the main `README.md`.
Without it, running `install.bat` will fail at `sc start KernelFuzzer`
with `ERROR_INVALID_IMAGE_HASH` (0xC0000428).

## Prerequisites

- Windows 10/11 host **that you own** — test-signing relaxes a
  kernel-load policy and must not be enabled on production systems.
- Visual Studio 2019/2022 (for `signtool.exe`) or a standalone Windows
  SDK install (`signtool.exe` ships in the SDK's `bin/<sdk>/x64/`).
- PowerShell 5.1 or later (for `New-SelfSignedCertificate`).
- The driver already built at
  `src\objfre_win7_amd64\amd64\KernelFuzzer.sys` (legacy path) or
  `src\x64\Release\KernelFuzzer.sys` (modern WDK).

## Step 1 — Enable test-signing on the host

```cmd
bcdedit /set testsigning on
shutdown /r /t 0
```

After the reboot, the desktop will display a "Test Mode" watermark in
the bottom-right corner. That watermark is the visible state of the
boot configuration; it does *not* by itself permit unsigned drivers —
the driver still has to be signed with a cert whose chain ends in a
root the system trusts.

## Step 2 — Create a self-signed code-signing certificate

Modern recipe (PowerShell, recommended):

```powershell
$cert = New-SelfSignedCertificate `
    -DnsName "KRzr Test Cert" `
    -Type CodeSigningCert `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyUsage DigitalSignature `
    -KeyExportPolicy Exportable

# Remember the thumbprint — Step 4 needs it.
$cert.Thumbprint
```

Legacy recipe (kept here only because some WDK docs still cite it;
`makecert.exe` is deprecated by Microsoft):

```cmd
makecert -r -pe -ss PrivateCertStore -n "CN=KRzrTestCert" KRzrTestCert.cer
```

## Step 3 — Export the certificate

The certificate must be installed in the local machine's
**Trusted Root Certification Authorities** and **Trusted Publishers**
stores so the kernel's signature verifier will accept it.

```powershell
# Export the public part to a .cer file
Export-Certificate -Cert "Cert:\CurrentUser\My\$($cert.Thumbprint)" `
                   -FilePath krzr-test.cer

# Install in the two stores the kernel verifier consults
certutil -addstore Root             krzr-test.cer
certutil -addstore TrustedPublisher krzr-test.cer
```

Optionally export the private part to a PFX so `signtool` does not
have to read it from the user's cert store:

```powershell
$pwd = ConvertTo-SecureString -String "krzr-dev" -Force -AsPlainText
Export-PfxCertificate `
    -Cert "Cert:\CurrentUser\My\$($cert.Thumbprint)" `
    -FilePath krzr-test.pfx `
    -Password $pwd
```

## Step 4 — Sign the driver

From the project root, after running `build.bat`:

```cmd
signtool sign ^
    /v ^
    /fd SHA256 ^
    /f krzr-test.pfx ^
    /p krzr-dev ^
    /tr http://timestamp.digicert.com ^
    /td SHA256 ^
    src\objfre_win7_amd64\amd64\KernelFuzzer.sys
```

Or, signing directly from the cert store by thumbprint:

```cmd
signtool sign ^
    /v ^
    /fd SHA256 ^
    /sha1 <thumbprint-from-step-2> ^
    /tr http://timestamp.digicert.com ^
    /td SHA256 ^
    src\objfre_win7_amd64\amd64\KernelFuzzer.sys
```

Verify the signature:

```cmd
signtool verify /v /pa src\objfre_win7_amd64\amd64\KernelFuzzer.sys
```

A successful verify reports `Successfully verified` and lists the
test-cert subject and timestamp.

## Step 5 — Install and load

Now `install.bat` will succeed:

```cmd
cd src
install.bat
```

`sc start KernelFuzzer` returns `SERVICE_RUNNING` instead of
`ERROR_INVALID_IMAGE_HASH`.

## Tear-down (when finished)

```cmd
cd src
uninstall.bat

certutil -delstore Root             "KRzr Test Cert"
certutil -delstore TrustedPublisher "KRzr Test Cert"

bcdedit /set testsigning off
shutdown /r /t 0
```

## Troubleshooting

| Symptom                                                | Cause                                                  | Fix                                                     |
|--------------------------------------------------------|---------------------------------------------------------|---------------------------------------------------------|
| `sc start` returns `0xC0000428` (`STATUS_INVALID_IMAGE_HASH`) | Driver not signed, or cert not in TrustedPublisher.    | Repeat Step 4 and confirm Step 3 added the cert.        |
| `sc start` returns `0xC0000022` (`STATUS_ACCESS_DENIED`)     | Not running as administrator.                          | Re-launch `install.bat` from an elevated cmd.           |
| `signtool` reports `SignerSign() failed` (-2147024891) | PFX password mismatch or wrong thumbprint.             | Verify password / thumbprint matches Step 2 output.     |
| No "Test Mode" watermark after reboot                  | `bcdedit /set testsigning on` was run without admin.  | Run `bcdedit` from an elevated prompt and reboot again. |
| `New-SelfSignedCertificate` not recognized             | Pre-Windows-8.1 / PowerShell <4.0 host.                | Use the legacy `makecert` flow in Step 2.               |

## Why this is a one-time setup

Steps 1, 2, 3 are per-host: once test-signing is enabled and the cert
is in the local stores, every subsequent build only needs Step 4
(re-sign). Add Step 4 to the bottom of `build.bat` once the
certificate exists, so that the build → install loop is a single
command.

## Security notes

- **Test-signing only.** The cert created here is for the developer's
  own kernel-debug VM. It must not be used to sign drivers shipped
  outside that VM, and the VM must not be re-purposed for production.
- **Cert lifetime.** `New-SelfSignedCertificate`'s default validity is
  one year. After expiry, repeat Step 2 and Step 4.
- **Production signing.** Drivers intended for non-test-signed
  Windows installs require an EV code-signing certificate and
  submission through the Microsoft Hardware Lab Kit (HLK) for
  attestation. KRzr does not target this path; it is a research tool.

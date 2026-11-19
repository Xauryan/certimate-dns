# IIS SNI certificate helper

Build the helper for the host architecture and install it as
`C:\Windows\System32\certimate-iis-bind.exe`. For example, on Linux or macOS
with Go 1.26.6 available:

```sh
GOTOOLCHAIN=go1.26.6 GOOS=windows GOARCH=amd64 go build -trimpath -o certimate-iis-bind.exe ./cmd/certimate-iis-bind
```

The helper uses the Windows machine certificate store and HTTP.sys, which
require administrator privileges. Use a dedicated, restricted OpenSSH account
with these privileges. Keep the executable and its policy in System32 and give
write access only to Windows administrators responsible for this installation.
Authorize one of the following forms per line in
`C:\Windows\System32\certimate-iis-bind.targets`:

```text
site.example.test
api.example.test:8443
```

A hostname by itself authorizes rotation of its existing SNI binding on port
443. A second column of `create` additionally permits creation of that
specific HTTP.sys SNI mapping. Configure the matching IIS website binding
separately. This helper supports named SNI bindings in the machine MY and
WebHosting stores.

Configure the `certimate-iis-bind` subsystem and constrain the dedicated user
to the helper in the Windows OpenSSH server configuration. Place the
`Subsystem` line in the global section and the `Match` block last, after
account settings:

```text
Subsystem certimate-iis-bind C:\Windows\System32\certimate-iis-bind.exe

Match User certimate-bind
    ForceCommand C:\Windows\System32\certimate-iis-bind.exe
    DisableForwarding yes
    PermitTTY no
```

If a deployment account belongs to Windows' Administrators group, retain the
host's administrator account and credential restrictions. Validate the
effective OpenSSH configuration with `sshd -t` before restarting the service
and verify that the dedicated user is restricted to the helper on that host.
In Certimate, create an **IIS SNI (Windows SSH helper)** access account with
the server's pinned OpenSSH SHA256 host-key fingerprint. Choose the matching
deployment provider and enter one host and optional port in the workflow.

The workflow sends the certificate and private key only through the
authenticated subsystem's input stream. The helper validates the chain, key,
hostname and validity, imports the certificate and checks the binding before
returning the public certificate fingerprint. Keep the previous certificate in
the machine store for rollback.

The Windows build and local SSH contract tests verify compile and protocol
behavior. The installed OpenSSH account policy, supported Windows build,
atomic HTTP.sys update and served TLS certificate require acceptance on the
selected host. The helper requires the
[HttpUpdateServiceConfiguration API](https://learn.microsoft.com/en-us/windows/win32/api/http/nf-http-httpupdateserviceconfiguration)
and fails closed when it is unavailable.

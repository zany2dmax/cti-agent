# Example org pack

A sanitized example of every file an org pack can hold. Copy it as a
starting point, then replace the notes with your organization's own:

```bash
cp -R examples/org-pack org
```

On a box installed from an upstream clone, use `/etc/cti-agent/org/`
instead, owned by root:

```bash
sudo cp -R examples/org-pack /etc/cti-agent/org
```

```bash
sudo chown -R root:root /etc/cti-agent/org
```

Delete any file you don't need: every one is optional. docs/org-pack.md says
what each file does and the rules the installer checks.

Everything here is invented. "Example Org", the team names and the
priorities are placeholders.

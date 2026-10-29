# abbasi26.certclock

An Ansible collection that ships the read-only [CertClock](https://github.com/Abbasi26/certclock) collector for Linux certificate files.

The playbook copies one Python script into a temporary directory on each host. Ansible deletes that copy afterwards. The script reads certificate files under the configured paths, shells out to `openssl` and prints JSON metadata: subject, issuer, validity, fingerprints and path. It never prints a private key, and it doesn't change anything on the host. `become` is off. The JSON is written on the controller.

## Install

```bash
ansible-galaxy collection install abbasi26.certclock
```

## Run

```ini
# inventory.ini
[certclock_linux]
web01.example.test
```

```bash
ansible-playbook abbasi26.certclock.certclock_linux -i inventory.ini
# optional overrides
ansible-playbook abbasi26.certclock.certclock_linux -i inventory.ini \
  -e '{"certclock_paths": ["/etc/ssl", "/opt/app/certs"], "certclock_output_dir": "./certclock-linux"}'
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `certclock_paths` | `/etc/ssl`, `/etc/pki` | Directories the collector searches on each host |
| `certclock_output_dir` | `./certclock-linux` | Controller directory for one JSON file per host |

Then import the result into CertClock (`pip install` from the [repository](https://github.com/Abbasi26/certclock)):

```bash
certclock import linux --db certclock.db ./certclock-linux/web01.example.test.json
```

Requirements on each host: SSH access as an account that can read the certificate paths, plus `python3` and `openssl`.

## License

MIT, copyright Wasaf Abbasi.

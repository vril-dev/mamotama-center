# [center] minimal preset

Use this preset when you want one standalone control-plane instance backed by the file store.

Before first real use, change:
- `auth.enrollment_license_keys`
- `auth.admin_read_api_keys`
- `auth.admin_write_api_keys`
- `storage.path` and `storage.sqlite_path` if you do not want local repo-relative data

Apply and validate with:

```bash
make preset-apply PRESET=minimal
make preset-check PRESET=minimal
```

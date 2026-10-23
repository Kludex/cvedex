# Manage your CNA

```console
$ cvedex org
Acme  acme
Roles      CNA
ID quota   1000
```

The ID quota is how many reserved, unpublished IDs your CNA can hold at once. See how much of it you use:

```console
$ cvedex org quota
Quota      1000
Reserved   12
Available  988
```

## List users

```console
$ cvedex org users
USERNAME           NAME          ROLES   STATUS
alice@acme.org     Alice Smith   ADMIN   active
bob@acme.org       Bob Jones             active
```

## Add a user

Org admins only:

```console
$ cvedex org add-user carol@acme.org --first Carol --last Diaz
Added carol@acme.org
Give them an API key with cvedex org reset-key carol@acme.org
```

Pass `--admin` to make them an org admin.

## Change a user

Org admins only. Pass what changes:

```sh
cvedex org update-user carol@acme.org --last Díaz-Ruiz
cvedex org update-user carol@acme.org --username carol.diaz@acme.org
cvedex org update-user carol@acme.org --admin=false
cvedex org update-user carol@acme.org --active=false
```

| Flag | Changes |
| --- | --- |
| `--first`, `--last` | Their name |
| `--username` | Their username |
| `--admin`, `--admin=false` | Gives or takes the org admin role |
| `--active=false`, `--active` | Deactivates them, or lets them in again. Their key stops working while inactive |

## Give a user a new API key

```console
$ cvedex org reset-key carol@acme.org
Replace the API key of carol@acme.org? The current key stops working. Yes
New API key for carol@acme.org:
  9f2c...
It is shown once. Store it now.
```

New users have no key until you run this. For existing users, the old key stops working at once.

!!! warning "The key is shown once"
    CVE Services does not keep it in a form anyone can read back. If it is lost, reset it again.

`reset-key` always asks first. Without a terminal, pass `--yes`.

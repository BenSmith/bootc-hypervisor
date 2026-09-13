#!/bin/bash
# Host setup for the forgejo-runner workload.
#
# Usage:
#   setup.sh enable    — mint a fresh registration token, prune the stale runner
#   setup.sh disable   — remove the minted token
#   setup.sh artifacts — print what enable() leaves on the host (read-only)
#
# Idempotent in both directions. Called by workloadctl enable/disable, before the
# cloud-init seed is built, so the token it writes is what the seed reads.
#
# WHY THIS EXISTS: a Forgejo registration token is one-shot — the first
# registration consumes it — so a rebuilt VM cannot replay a stored one. Minting
# fresh on every provision (and feeding it to the seed through the credstore) is
# what makes `disable --purge` + `enable` a working reset. The Forgejo *admin*
# credential never leaves the host; the guest receives only the consumable
# registration token.
set -euo pipefail

WORKLOAD_NAME="${WORKLOAD_NAME:?not set — run via workloadctl enable/disable}"
WORKLOAD_INSTANCE_DIR="${WORKLOAD_INSTANCE_DIR:?not set — run via workloadctl enable/disable}"

# Unscoped credstore names. The cloud-init template form ${SECRET?name} admits no
# '/' (see secrets_template.py), so the minted token must be a plain name; the
# admin token is unqualified for the same reason, plus it is read by this script
# rather than by a workload.
ADMIN_CRED=/etc/credstore.encrypted/forgejo-admin-token
TOKEN_CRED=/etc/credstore.encrypted/forgejo-runner-token
RUNNER_NAME="${WORKLOAD_NAME}-runner"

forgejo_url() {
  # The instance TOML, not the bundle: `init --as` renames the instance and the
  # operator edits its copy. Same read Sunshine's setup.sh does.
  python3 - "$WORKLOAD_INSTANCE_DIR/workload.toml" <<'PY'
import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
tv = d.get("vm", {}).get("cloud_init", {}).get("template_vars", {})
print(tv.get("FORGEJO_URL", ""))
PY
}

# Delete any existing runner with our name so re-provisioning does not leave an
# offline row behind per reset. Best-effort: a list/delete failure is a
# housekeeping miss, not a reason to fail the provision.
prune_stale() {
  python3 - "$FORGEJO_URL" "$ADMIN_TOKEN" "$RUNNER_NAME" <<'PY' || echo "  (could not prune stale runners)"
import json, sys, urllib.request
url, token, name = sys.argv[1], sys.argv[2], sys.argv[3]
auth = {"Authorization": "token " + token}

def call(req):
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read()

try:
    runners = json.loads(call(urllib.request.Request(
        url + "/api/v1/admin/actions/runners", headers=auth)))
except Exception as e:
    print("  list runners failed: %s" % e)
    raise SystemExit(0)

for run in runners if isinstance(runners, list) else []:
    if run.get("name") == name:
        try:
            call(urllib.request.Request(
                "%s/api/v1/admin/actions/runners/%s" % (url, run["id"]),
                method="DELETE", headers=auth))
            print("  pruned stale runner id=%s" % run["id"])
        except Exception as e:
            print("  could not prune runner id=%s: %s" % (run["id"], e))
PY
}

case "${1:-}" in
  enable)
    if [ ! -s "$ADMIN_CRED" ]; then
      {
        echo "WARNING: no Forgejo admin API token at $ADMIN_CRED"
        echo "  The VM will provision, but the runner cannot register and will"
        echo "  sit idle. Create a Forgejo token with admin scope, then:"
        echo "    workloadctl secret create forgejo-admin-token"
        echo "    workloadctl enable $WORKLOAD_NAME      # re-run to mint"
      } >&2
      exit 0
    fi

    FORGEJO_URL="$(forgejo_url)"
    if [ -z "$FORGEJO_URL" ]; then
      echo "ERROR: [vm.cloud_init.template_vars].FORGEJO_URL is empty in" >&2
      echo "  $WORKLOAD_INSTANCE_DIR/workload.toml — nothing to register against." >&2
      exit 1
    fi
    ADMIN_TOKEN="$(systemd-creds decrypt "$ADMIN_CRED" -)"

    prune_stale

    # GET /admin/actions/runners/registration-token. Deprecated in Forgejo 15
    # ("use the web UI or /admin/actions/runners instead") but still present;
    # the modern endpoint registers the runner outright and returns its own
    # token, which forgejo-runner's `register` does not accept. Revisit when the
    # deprecated endpoint is removed. The response is a bare JSON string, but
    # accept a {"token": ...} object too so a shape change is not a silent empty
    # token.
    token="$(curl -fsS -H "Authorization: token ${ADMIN_TOKEN}" \
              "${FORGEJO_URL}/api/v1/admin/actions/runners/registration-token" \
            | python3 -c 'import json,sys
d = json.load(sys.stdin)
print(d if isinstance(d, str) else d.get("token", ""))')"
    if [ -z "$token" ]; then
      echo "ERROR: Forgejo returned an empty registration token." >&2
      exit 1
    fi

    # Seal it under the name the seed's ${SECRET?forgejo-runner-token} resolves.
    # systemd-creds binds the plaintext to the name, so the seal name and the
    # credstore basename must agree. mkdir first: systemd-creds will not create
    # the credstore directory, and a host that has never run `secret create`
    # does not have one.
    install -d -m 0700 /etc/credstore.encrypted
    printf '%s' "$token" \
      | systemd-creds encrypt --name=forgejo-runner-token - "$TOKEN_CRED"
    chmod 0600 "$TOKEN_CRED"
    echo "  minted registration token for ${FORGEJO_URL} (runner ${RUNNER_NAME})"
    ;;

  disable)
    rm -f "$TOKEN_CRED"
    ;;

  artifacts)
    # Read-only, one "kind ref" per line. See host_setup.run_host_setup. Written
    # as an `if`, not `[ -e ] && echo`: under `set -e` a false test would become
    # the script's exit status and read as "does not implement the action".
    if [ -e "$TOKEN_CRED" ]; then
      echo "file $TOKEN_CRED"
    fi
    ;;

  *)
    echo "usage: $0 {enable|disable|artifacts}" >&2
    exit 1
    ;;
esac

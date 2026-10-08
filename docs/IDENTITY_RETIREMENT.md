# Quorum-authorized identity retirement

This is an offline incident-response mechanism for an owned deployment. It does
not distribute policies automatically, certify operator independence or instantly
disconnect processes that have not restarted. Before a compromise response,
stop every enrolled authority, relay and gateway, distribute the reviewed policy,
update replacement pins, and restart using persistent state. Stop applications
and retain their containment while the routing services are unavailable.

## Policy contract

The policy binds version 1, a nonzero generation, the exact identity/name/public-key
authority-set digest and a cumulative set of up to 512 retired Ed25519 identities.
Distinct signatures exceeding two thirds of the configured authorities are
required. Four authorities require at least three signatures. Duplicate keys or
aliased votes cannot inflate this count. The policy signing domain differs from
directory and relay signatures. A policy is not a directory consensus document.

Each node persists the accepted generation, digest and retired set. Older
generations, conflicting content at the same generation, and removal of previously
retired identities fail startup. Authority replacement needs updated authenticated
pins and a newly signed higher policy generation preserving all retired identities.
The existing authority-key migration still requires independent out-of-band trust;
a compromised old authority cannot authorize its replacement alone.

After enrollment, omitting `--revocation-policy`, supplying an invalid policy or
losing access to the rollback journal stops startup. Journal paths are derived from
the identity path for authorities and guard-state path for other roles, using the
`revocation.json` extension. Preserve these paths across upgrades; switching or
deleting state is not a safe recovery procedure. State parent directories and the
host must remain operator-controlled. A compromised administrator can remove
local security state and is outside this mechanism's protection.

Policy check-and-commit uses an exclusive adjacent `.lock` file. A crash during
startup may leave this lock. Stop every process using that state, inspect the
policy and journal, and only then explicitly remove the stale lock and restart.
Do not delete the journal, run parallel maintenance on it or auto-clear locks.

The policy has no clock-based expiry or online freshness service: an unenrolled or
offline node does not learn a newer policy by itself. Operators must confirm the
approved generation/digest through their authenticated coordination channel and
record rollout acknowledgements. This is a deliberate scoped operational contract,
not a claim of completed network-wide online revocation.

## Offline signing ceremony

Use `anonguard-identity-policy` from a verified build. Obtain the full authority set
and compromised public pins through an authenticated channel. Each signer must
review the entire retired list and generation, independently authenticate the
authority set, and use only their own private key locally. Never move signing keys
to a central collector or include private keys in command arguments.

Create an unsigned template with the complete cumulative list:

```sh
anonguard-identity-policy create --generation 1 \
  --authority-keys 'a0:PUBLIC_HEX_0,a1:PUBLIC_HEX_1,a2:PUBLIC_HEX_2,a3:PUBLIC_HEX_3' \
  --retire 'RETIRED_PUBLIC_HEX' --output policy-unsigned.json
```

Each authority produces a separate output, passing the partial policy to the next
signer over the authenticated coordination channel:

```sh
anonguard-identity-policy sign --input policy-unsigned.json \
  --authority-id a0 --identity-key-path /private/a0.key \
  --authority-keys 'a0:PUBLIC_HEX_0,a1:PUBLIC_HEX_1,a2:PUBLIC_HEX_2,a3:PUBLIC_HEX_3' \
  --output policy-a0.json
```

Signers a1 and a2 repeat with their own IDs/keys and the preceding output. The tool
rejects missing keys without creating replacements, refuses output overwrite, and
requires the signer key and policy context to match the supplied authority set.
Verify the completed quorum before distributing it:

```sh
anonguard-identity-policy verify --input policy-a0-a1-a2.json \
  --authority-keys 'a0:PUBLIC_HEX_0,a1:PUBLIC_HEX_1,a2:PUBLIC_HEX_2,a3:PUBLIC_HEX_3' \
  --quorum 3
```

The example placeholders must be replaced by real 64-character public pins. An
empty `--retire` list supports initial enrollment; it does not permit clearing a
previous retirement. Preserve reviewed ceremony artifacts privately.

## Runtime enforcement

Add `--revocation-policy /private/policy.json` to each authenticated routing role's
arguments alongside its existing pinned `--authorities`, `--authority-keys` and
quorum settings. The packaged DynamicUser service needs an explicitly reviewed
`LoadCredential` drop-in for a root-private policy; reference it with the service's
credential-directory path in its existing runtime arguments. Do not make private
configuration world-readable to work around service access.

Authorities refuse retired relay registrations and gossip descriptors. A previously
frozen vote containing a retired identity is refused until a new epoch; it is never
rewritten at the same epoch. Clients verify the full canonical directory certificate
before excluding retired relays from selection and relay-extension admission.
Persisted guard pins remain pinned: retirement may leave no usable guard, requiring
the existing explicit operator migration rather than automatic guard replacement.

Configured retired authority, private bridge or local routing identities fail
startup. Update affected bootstrap/bridge profiles using authenticated replacement
pins. Raw/open proxy and tracker modes are excluded from explicit enrollment.
Policies authorize retirement, not exceptions to TLS, quorum, identity binding,
destination validation or application containment.

These controls require coordinated restart to terminate old sessions. They cannot
stop an attacker operating a compromised relay or force older unenrolled clients
to distrust it. Online distribution, automatic emergency session cancellation and
independently reviewed rotation remain further work.

## State-input boundaries

On Unix, keys and runtime state/configuration inputs reject final symlinks and
special files without blocking on FIFOs. Parent-path containment still depends on
operator-controlled directories. Identity keys are exactly 32 bytes with private
Unix permissions; guards/transport profiles are at most 64 KiB, rollback snapshots
4 KiB, proxy files 1 MiB, retirement policies/journals 256 KiB and authority vote
journals 16 MiB with at most thirteen retained snapshots. Corrupt or oversized
files fail; startup does not erase trust state to recover. Native Windows key ACL
and reparse-point assurance remain a separate platform gate.

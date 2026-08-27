# Investigation: editing Forescout Network Policies programmatically

## Goal

Understand how a policy edit made in the Forescout GUI actually reaches the
engine and propagates to appliances, with the end goal of eventually editing
policies directly from the forescout-lookup web app instead of only reading
them.

## Environment used for this investigation

- EM: `192.168.22.215` (hostname `Farcarem` / `farncarem` -- this was
  promoted from REM to EM partway through this session; `.210` is now the
  REM).
- Appliances: `192.168.22.212`, `192.168.22.213`.
- Test policy: **"CrowdStike Test"** (that's the real spelling in the DB --
  not "CrowdStrike"), `pol_id = -2688478297107593235`.
- Windows GUI Console client installed at
  `C:\Users\dhone.YUBIQUE0\Forescout Console 9.1.4` (v9.1.4), on this same
  workstation (`192.168.22.253`).

## What's conclusively proven

### 1. Canonical policy storage is XML on disk, not a single `np_rules.xml`

- `/usr/local/forescout/etc/npexpr/rule<rule_id>.xml` -- the actual
  **condition logic** for one rule, a clean, human-readable
  `EXPRESSION`/`CONDITION`/`FILTER` tree (`AND`/`OR`/`PARENTHESIS` nesting,
  operators like `equals`/`any`, literal values). This is the file to target
  for programmatic editing of conditions.
- `/usr/local/forescout/etc/nprules.xml` -- aggregate of every rule
  (`<RULE>`/`<INNER_RULE>` elements, one `RULE_CHAIN` per policy). ~30k
  lines on this lab EM.
- `/usr/local/forescout/etc/nptree.xml` -- the policy tree/ordering
  structure (which policies exist, in what order). Sub-rules aren't listed
  here, only top-level policies.
- `/usr/local/forescout/backup/policy_backup.<timestamp>.zip` -- an
  automatic pre-change backup, written just before the above on every save.

Confirmed live by editing a policy in the GUI and watching file mtimes:
backup zip, then `npexpr/rule<id>.xml`, then `nprules.xml`, then
`nptree.xml` -- all within about 750ms, and **before** any Postgres write.

### 2. Postgres `np_rules` (in the `root` database) is a derived index, not canonical

- Schema: `rule_id, pol_id, rule_name, description, eval_fields, span`.
- `eval_fields` is *only* a colon-separated list of raw field **names**
  the rule references (e.g. `cs_device_id:cs_hostname:mac:`) -- confirmed
  across every row in the table, including complex real policies. It never
  holds operators or values. Best guess: an index so the engine can cheaply
  answer "which rules care about field X" without re-parsing XML on every
  host update.
- Two `INSERT INTO np_rules (...)` land ~1s *after* the XML files, executed
  by OS user `_fsservice` / Postgres role `root`.
- No triggers exist on `np_rules` (checked `pg_trigger`) -- so even a
  perfectly-formed write has no automatic side effect. Whatever makes a
  change "live" is a separate, explicit action the backend takes, not a
  DB-reactive mechanism.

### 3. EM -> appliance propagation

- CCU (`forescout.cc.ccu.CCU`, the core engine process) listens on
  **TCP 13000**, TLS. The EM keeps persistent, already-open TLS connections
  into each appliance's own CCU on port 13000 (`ss -tnp` shows two
  established connections per appliance).
- The identical XML files land on both appliances within the same minute as
  the EM's own write (confirmed byte-for-byte identical
  `npexpr/rule<id>.xml` on `.212` and `.213`).
- `.212`'s local `datapublisher` plugin log showed a RabbitMQ-consumer
  thread (`datapublisher.queue.policy-N-<id>`) firing ~2-3s after the EM
  commit -- real propagation-timing evidence. `.213` didn't show the same
  log line in the same window even though its row/file both arrived
  correctly -- inconclusive on the exact log path there, not a different
  mechanism (same architecture confirmed on both: local RabbitMQ broker per
  box, same queue names, same CCU-on-13000 setup).
- Each box (EM and every appliance) runs its **own local** RabbitMQ broker
  and Postgres -- it's not one shared message bus.

### 4. XML/DB edits alone do NOT make a live change (important negative result)

Two independent tests, both on the live "CrowdStike Test" policy's
"CrowdStrike & MAC" sub-rule (`rule_id 4083573323539392921`):

- **Test A**: deleted `npexpr/rule4083573323539392921.xml` and its
  `<INNER_RULE>` block from `nprules.xml`, left the Postgres row alone.
  GUI (which auto-refreshes) showed **no change**.
- **Test B**: restored A, then deleted the Postgres `np_rules` row instead,
  left XML alone. GUI showed **no change** again.

Conclusion: **neither store drives the live GUI/evaluation state.** The
real "make it live" step is something the `webgui`/`adminapi` backend does
explicitly when handling the save request -- almost certainly a direct
call into CCU -- and it's *separate* from (though it also triggers) the
XML+DB writes. Both test states were restored from backup afterward and
verified clean.

### 5. Port 13000 requires mutual TLS, and the client does certificate pinning

- `openssl s_client`/`curl` against `127.0.0.1:13000` completes a TLS
  handshake (real cert, `CN=counteract_service`, self-signed, ECDSA) but
  gets zero HTTP response on any path tried -- not a REST API, some other
  (likely Java-serialization-based) protocol on top of TLS.
- Sending arbitrary bytes after the handshake got an immediate
  `bad_certificate` TLS alert -- the server expects the *client* to also
  present a certificate (mutual TLS), matching the EM<->appliance trust
  model above.
- Built a Python TLS listener presenting a fake self-signed cert on
  `192.168.22.253:13000` and pointed the real Windows Console client at it.
  Result: `CERTIFICATE_VERIFY_FAILED: self-signed certificate` -- the
  client aborts at server-cert validation, before it would ever send its
  own client cert.
- Tried defeating this by adding the fake cert into the Console's own trust
  material two different ways:
  - Repointed `javax.net.ssl.trustStore`/`trustStorePassword` in the
    Console's `fs.properties` at a brand-new trust store containing the
    fake cert. **No effect** -- app doesn't use the standard JVM property,
    confirming it builds its own `SSLContext`/`TrustManager` in code.
  - Found the *actual* password (`tempPass`, see `fs.properties` on either
    the EM or the Console install --
    `cam.temp.password.for.public.keystore`) and used it to legitimately
    `keytool -importcert` the fake cert straight into the real
    `etc/keys/nodePUBLIC` keystore that `cam.keystore.public.file` points
    at. **Still no effect** -- identical rejection.

  Since adding a trusted CA entry via the *correct* password into the
  *actual* referenced keystore still didn't change the outcome, this isn't
  a "wrong file" or "wrong password" problem -- the client is doing real
  **certificate pinning** (checking the server's cert against a specific
  expected identity/fingerprint), not generic chain-of-trust validation.
  That can't be defeated by adding another trusted CA; it needs the real
  EM certificate + private key, which lives in a password-protected Java
  keystore (`etc/keys/node`, JKS format) whose password isn't in any config
  file found so far.

  **All test changes were reverted** -- `nodePUBLIC` and `fs.properties`
  restored from backup and verified (`mitmtest` alias gone, trustStore
  properties back to original). The Console client is back to its
  untouched state.

### 6. BREAKTHROUGH -- the `node` keystore password is deterministically derivable, not fixed

A colleague found Forescout KB guidance for a "node failing to connect"
scenario: back up `etc/keys/node`, run `fstool set_certs -q` to regenerate
it, then `fstool service restart`. Followed this on the EM (backed up the
original to `etc/keys/node.bak2` first) and traced exactly what it does:

- `set_certs.pl` (`/usr/local/forescout/lib/fstool/commands/set_certs.pl`)
  copies `nodePUBLIC` to a temp file, runs
  `forescout.cam.FSKSpassChange` on it with the literal argument
  `'tempPass'`, then `forescout.cam.NodeGenKey` to generate a fresh
  keypair into it, then renames the temp file over `etc/keys/node`.
- Disassembled `FSKSpassChange.changePass()` (`javap -c -p`): it opens the
  keystore using the passed-in `tempPass` (the *old* password -- this
  matches `nodePUBLIC`'s already-known password), then re-saves it using
  a *different* password obtained from
  `forescout.common.cipher.FSKSP.get()` -- **that's the real password for
  `etc/keys/node`**, not `tempPass`.
- `FSKSP.getImpl()` first checks a `fs.kspass` property override (not set
  on this EM), otherwise derives the password deterministically from
  `UserPasswordEncryptionManager.sharedInstance().getStringForKey()`
  (a per-machine seed) through a custom scramble/BASE64/alphanumeric-filter
  algorithm, producing a 10-character result.
- Rather than hand-reimplementing that algorithm, just invoked
  `FSKSP`'s own `main()` (which already prints exactly this) directly,
  reusing the same Perl helper infra (`util.ph`'s `setClassPath()` /
  `getJavaCommand()`) that `set_certs.pl` itself uses:

  ```perl
  require "forescout/util.ph";
  setClassPath();
  my $cmd = getJavaCommand("-DFSTrace.nobanner=true", "forescout.common.cipher.FSKSP");
  system "$cmd > /tmp/kspass_out.$$";
  ```

  Run from `/usr/local/forescout` on the EM (or the Console install, same
  jar/class is bundled there too). **This is fully reproducible any time
  it's needed again -- the actual value is deliberately not written here,
  see CLAUDE.md's no-secrets-in-docs rule.** It's a real, working password
  for the regenerated `etc/keys/node` keystore -- confirmed via
  `keytool -list`, which showed a `PrivateKeyEntry` aliased `fsnet` (the
  node's real identity) among 109 trust entries.

**RESOLVED -- rolled back, EM is fully healthy again.** What happened,
for anyone picking this back up:

`etc/keys/node.bak2` = original keystore (untouched backup).
`etc/keys/node` = freshly regenerated keystore (new self-signed keypair,
alias `fsnet`). **`fstool service restart` WAS run** -- the EM came up
fine, but its new self-signed identity isn't CA-signed, so **all
appliances disconnected**: `.212`, `.213`, the REM `.210` (two other,
already-offline-before-any-of-this hosts, `172.16.1.129`/`.130`,
unaffected either way). Confirmed via `.212`'s own trace log:
`java.security.cert.CertificateException: Signature not verified` --
exactly what you'd expect from a self-signed cert nothing else trusts.

Tried to properly re-establish trust rather than just roll back
straight away. `fstool certool` is the real tool for the internal CA
(`lsca`, `lsend`, `csr`, etc. -- see `fstool certool` with no args for
the full list) and the newly-generated end-entity cert had its own CSR
sitting right there (`etc/cert/endentity/store/<uuid>/cert.csr.txt`), but
no CA-signing subcommand was found in that list at all (no `sign`,
nothing obviously it) -- and `etc/cert/ca/` (7 trusted CA `.pem` files on
this EM) holds **no private key**, so this EM can't self-sign into that
chain either.

Went looking for how trust actually works instead of guessing further:
`.212`'s own `etc/cert/endentity/store/` had a cert with
`CN=farncarem.yubique.com`, issued by David's real internal CA
(`Intermediate.yubique.com`) -- the exact same cert this session found
much earlier serving Apache on port 443. That looked like the answer
(the appliance already trusts *that* specific cert, and David has a
matching key on his own machine, `ca/intermediate/server/private/
farncarem.Yubique.com.key.pem` (its passphrase is not recorded here --
see CLAUDE.md's no-secrets-in-docs rule -- but it's the same one already
in use for this app's own HTTPS cert; confirmed openable with
`openssl rsa -check`). **But it wasn't**: its SHA-256 fingerprint
didn't match `.212`'s stored copy, and -- the real surprise -- restoring
the *original* `node.bak2` and checking its own `fsnet` entry's
fingerprint didn't match `.212`'s stored trust entries either, even
though that original keystore is what was genuinely working minutes
earlier. So the mutual-TLS trust CCU actually validates against for
port 13000 is not simply "does the peer's JKS `node`-keystore identity
match one of my stored `endentity` certs" -- there's a layer here still
not understood (possibly it's the CRL/chain-validation path via `lsca`
rather than a direct fingerprint match, possibly something else
entirely). **Flagged and left unsolved rather than guessed at further.**

**What actually fixed it**: plain rollback.
`mv etc/keys/node etc/keys/node.selfsigned-2026-08-27` (kept, not
deleted, in case it's useful later) then `mv etc/keys/node.bak2
etc/keys/node`, then `fstool service restart`. Took about 3 minutes to
fully settle; confirmed via `fstool service status` polling --
`.212`/`.213` back under "Connected Forescout Appliances", REM `.210`
"connected". Cross-checked with a real `lookup` call through the actual
forescout-lookup app afterward -- full, correct data back for `.212`,
`all_targets` correctly listing `.210`/`.212`/`.213`. EM is exactly back
to its pre-session state; nothing left broken.

**If this gets picked up again**, the productive next step is almost
certainly still the DevTools HTTP capture from section "Recommended next
step" below -- not more `certool`/keystore spelunking. The one new lead
worth keeping in mind: whatever CCU validates a peer's cert against for
port 13000 evidently isn't a simple stored-fingerprint match, so if
that mechanism ever needs to be understood properly, it likely means
finding CCU's own logging/config for *how* it invokes certificate
validation (not just the trust material itself), or asking Forescout
support directly rather than reverse-engineering it blind on a live lab.

### 7. Console-side password derivation -- blocked on environment bootstrap, not attempted further

Tried reusing the same `FSKSP` trick against the Windows Console's own
bundled copy (`GuiManager/current/lib/java/forescout.jar`), to get a real,
already-trusted client identity for testing the 13000 protocol directly
(bypassing the GUI entirely, and independent of the appliance-trust mess
above -- the EM's own trust of an *existing* Console client cert is
unaffected by regenerating the EM's own identity).

Invoking `forescout.common.cipher.FSKSP` directly via `java.exe` with a
manually-reconstructed classpath got past classpath issues (jars are
scattered across `lib/java/<subdir>/*.jar`, not just `lib/java/*.jar` --
recursive `Get-ChildItem -Filter *.jar` fixes that), but then hit:

```
Exception in thread "main" java.lang.ExceptionInInitializerError
  ... FSGlobalTrace.sharedInstance() is null ...
Caused by: java.lang.NullPointerException
```

`FSKSP.main()` sets up its own Guice injector (`IndependentGuiceModule`)
before calling `FSUtil.init(2)`, which is exactly what `set_certs.pl`'s
Perl-wrapped invocation on the EM does too -- and that worked fine there.
The difference must be additional JVM properties `util.ph`'s
`getJavaCommand()` sets on the EM side that weren't replicated by hand on
Windows (trace/log directory config, most likely, given the NPE is inside
`FSGlobalTrace`). No launcher script/`.vmoptions`/`.ini` file was found
in the Console install to copy the real invocation from (the actual
Console launcher is a bare compiled `.exe`, not a readable config).

**Not attempted**: hand-reimplementing `FSKSP.getImpl()`'s scramble
algorithm from the disassembled bytecode directly in Python (skipping the
whole Java app framework) -- the logic is fully captured in the earlier
`javap -c -p FSKSP.class` output further up this doc's history, so it's
reproducible from that if picked up later, but doing it by hand risks
subtle bugs (Java `Math.abs`/char-cast semantics) that would be hard to
verify without a working keystore to test against on the Console side.

### Other things checked, dead ends

- `fstool help -a` (full command list): `engine` (status/kill/dump, no
  reload), `npstats` (read-only stats), `spt` (unrelated -- Security Policy
  Template/segmentation), `adminapi`/`webgui` (bare launchers, need
  undocumented arguments -- didn't pursue further, too risky to guess at on
  a live core process).
- `adminapi.log`/`webgui.log` log nothing at INFO level for the actual save
  request -- would need to raise log verbosity (not attempted, bigger/more
  invasive change).
- `Install_Management.exe` (the 326MB Windows Console installer, also
  findable on the EM at
  `/usr/local/forescout/webapps/portal/management-setup/InstData/windows/`)
  is not a plain zip-appended installer (no `PK` signature anywhere in the
  file) -- couldn't extract it for inspection without `7z` (no package
  repos available on the EM appliance to install it).
- `objects` table in the `root` DB (generic key/type/data blob store) is
  completely empty -- not where anything policy-related lives.
- No column named anything like `expression`/`criteria`/`tree`/`condition`
  exists anywhere in the whole Postgres schema (checked
  `information_schema.columns`).

## Recommended next step

**Capture the real HTTP request the browser GUI sends on save**, via
DevTools:

1. Open DevTools -> Network tab -> check "Preserve log" -> optionally
   filter to Fetch/XHR.
2. Edit the "CrowdStike Test" policy in the browser GUI and save.
3. Find the `POST`/`PUT` request(s) that fired around the save.
4. Right-click -> Copy -> Copy as cURL, paste back for analysis.

This sidesteps the whole client-cert/13000-protocol question entirely,
since the browser already has a working, authenticated way to make the
change -- far less effort than either reverse-engineering CCU's binary
protocol or extracting the `node` keystore's real password (would likely
require a JVM heap-dump-level attack, not attempted -- poor effort/payoff
given this alternative).

## Credentials/passwords referenced (not stored here)

- EM Apache/Console keystore "temp" password: see `cam.temp.password.for.public.keystore`
  in `/usr/local/forescout/etc/fs.properties` on the EM, or the same key in
  the Console install's `GuiManager/current/etc/fs.properties`.
- Console GUI login used during this investigation: ask David (not
  recorded here).

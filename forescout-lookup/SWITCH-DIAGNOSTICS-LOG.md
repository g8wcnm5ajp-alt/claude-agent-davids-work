# Switch Plugin Diagnostics Log

Ad-hoc findings from reviewing the `sw` plugin logs (`/usr/local/forescout/log/plugin/sw/`) on the
appliances (`.212`, `.213`). Not exhaustive documentation of the switch plugin -- just a record of
things investigated live, so a later session doesn't have to re-derive them.

---

## 2026-08-27 -- Juniper 192.168.22.223 dead NETCONF session (live test, fixed)

**Symptom**: reviewing `.212`'s `sw.log` for the preceding 90 minutes showed switch `192.168.22.223`
(Juniper, managed via `FSExpectNetconf`) failing every single MAC-table read attempt -- 570 failed
calls in the window (380 `switch_query_self_mac_cb` + 190 `_switch_query_macs_cb`), plus 105
relogin/lost-connection cycles, all erroring `CLI connection is invalid.`. The other switches on
`.212` (three Cisco boxes, SNMP-polled) and the one Cisco switch on `.213` (CLI-expect-polled) were
all healthy in the same window -- this was isolated to `.223`.

**Root cause investigation**:
- Network/transport layer confirmed healthy from `.212`: ping ~2ms, port 22 open, SSH key exchange
  negotiates cleanly and the switch correctly advertises `publickey,password,keyboard-interactive`.
- The actual plugin login command: `ssh ... root@192.168.22.223 -s netconf` (NETCONF-over-SSH
  subsystem, not a CLI shell -- different from how the Cisco switches are polled).
- The failure signature in the log: `FSExpectNetconf::handle_password_ack:459: received2:EOF`,
  immediately after the password is sent -- the switch was closing the NETCONF subsystem session
  right after authentication, before the plugin's expected `<hello>` handshake arrived.
- Present in every rotated log checked going back several days -- a persistent condition, not a
  transient blip, and unrelated to any same-day appliance work (this was investigated the same
  session as an unrelated EM keystore/cert rollback, but that only touched EM<->EM/appliance trust,
  never appliance<->switch NETCONF).
- Likely causes narrowed to (a) stale/incorrect credentials in the switch's Forescout profile, or
  (b) NETCONF service/login-class restricted on the Junos device itself. Didn't go further -- no
  access to the stored switch credentials or to the Junos device directly; the correct next step
  was the Console's switch profile (Tools -> Switches -> 192.168.22.223) to re-test/re-enter
  credentials.

**Fix**: David corrected it from the Console side (exact change not visible from the appliance log).

**Live re-test, confirmed working** -- from `.212`'s `sw.log`, using the Console's "Test" action:
```
15:32:07  main::switch_query_macs_test_cb ... num_macs[1] ... (climbing to num_macs[55])
15:32:07  device change: macDiscoveryStatus EMPTY -> NOT_EMPTY, sw_mac_discovery_status 0 -> 55
```
Full MAC table populated from empty in one pass -- 55 entries. NETCONF session is healthy again.

**Measured steady-state cadence post-fix** (direct from the log, not inferred):
```
15:32:46  <get-interface-information/>
15:32:50  <get-ethernet-switching-table-information/>   -- MAC table read
15:33:47  <get-interface-information/>
15:33:51  <get-ethernet-switching-table-information/>
15:34:48  <get-interface-information/>
15:34:52  <get-ethernet-switching-table-information/>
```
~61s between poll cycles, ~4s for the actual retrieval within each cycle. Matches the switch's own
profile config exactly (pulled from the same log's `plugin_request_cb` profile dump):
`profile_sw_mac_discovery_rate=60` (seconds), method `auto`.

**ARP note**: `arpStatus` stayed `UNKNOWN` before and after the fix -- expected, not a symptom. This
switch's profile has `profile_sw_arp_discovery=false` (ARP discovery is off by design for this
device). Configured-but-dormant values: `arp_discovery_rate=600` (10 min), `arp_refresh_rate=16200`
(4.5 hr), `arp_read_not_write_method=snmp`. Also saw one secondary, low-priority error during the
retest -- `FSSwitchJuniper::_juniper_init_snmp: SNMP session not defined, Required userName not
specified` -- harmless while ARP-via-SNMP is disabled for this profile, but worth knowing if it's
ever turned on.

---

## 2026-08-28 -- Policy tree Current View / Graphic View always show "No matched, enabled policies" (not a UI bug -- a tree-scope gap)

**Symptom**: David reported both views under a host's Policy tree card appear broken.

**Investigated live** with Playwright driving the actual deployed app (real login, real lookup, both
tabs clicked): zero JS console errors, both `.tree-view-tab-btn`s switch correctly, the Graphic view's
SVG renders cleanly (confirmed 2712 nodes drawn with the "show only matched" filter unchecked). So the
rendering code itself is fine.

**Root cause**: `build_policy_tree()` (`webapp-query.py`) intentionally scopes the tree to only the
`NINHS` top-level folder in `nptree.xml` -- its own comment says the other ~651 rules are "a dormant
template pack under different top-level folders, not worth shipping to every page load." That
assumption no longer holds: found a `Test-Polices` folder (with a `Test-SNOW` sub-folder) containing
rules that are **actively matching real hosts right now** -- confirmed via fresh `eval_status` rows on
both `.212` and `.213` (timestamps as recent as today 06:29), whose `rule_id`s exist in `nprules.xml`/
`nptree.xml` but sit outside `NINHS`, so `_parse_policy_folder`'s NINHS-only walk never includes them.

Since `/api/matched/<ip>` pulls from Postgres `np_action`/`eval_status` with no folder-scope
restriction, but `/api/policytree` only ever contains the NINHS subtree, any host whose recent matches
land in `Test-Polices` (which was most of what I sampled) shows a real match ID that then can't be
found anywhere in the tree the UI actually draws from -- both views correctly render "No matched,
enabled policies found for this host", which is silently wrong rather than broken outright. Verified
this isn't a stale cache: grepped `nprules.xml`/`nptree.xml` directly on the EM, bypassing the app's
own `policy_tree_cache.json`.

**Not yet fixed** -- David's call, 2026-08-28: report only for now, no code change. Options on the
table for later: (a) widen `build_policy_tree()` to include every top-level folder, not just NINHS
(simplest, but the tree grows well past 2712 nodes), or (b) keep NINHS-only but have the UI surface
"N matched rule(s) exist outside the displayed tree" instead of a bare "no matches" when
`/api/matched` returns IDs the tree doesn't contain.

---

## Reference: observed MAC/ARP read cadence by switch (90-min sample, 2026-08-27 13:47-15:20)

| Appliance | Switch IP | Type | Poll style | MAC-table cadence | ARP cadence |
|---|---|---|---|---|---|
| .212 | 192.168.22.223 | Juniper | NETCONF | ~60s (post-fix, measured) | disabled (profile setting) |
| .212 | 10.10.20.176, 20.10.10.175, 10.10.20.178 | Cisco | SNMP | ~30 min (self-mac check interval) | bundled into same ~30 min cycle |
| .212 | 192.168.22.1 (gateway) | -- | SNMP `at` table | -- | ~2 min |
| .212 | 192.168.22.2 (gateway) | -- | SNMP `at` table | -- | much less frequent (~20+ min) |
| .213 | 192.168.22.221 | Cisco | CLI expect | irregular, ~16-28 min gaps between full polls in sample window | no active read observed in sample window (relies on cached/passed-in data) |

To confirm a cadence with confidence (not just one sample), plan on watching for 2-3 full cycles:
~2-3 minutes for a 60s-interval switch, ~60-90 minutes for a ~30 min-interval switch.

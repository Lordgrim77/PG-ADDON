import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

import httpx

# Add repository root to sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import route_manager as rm


def make_wg_outbound(tag: str, endpoint: str = "162.159.192.1:2408", mtu: int = 1280, keep_alive: int = 20) -> dict:
    ob: dict = {
        "tag": tag,
        "protocol": "wireguard",
        "settings": {
            "secretKey": f"privkey-{tag}",
            "address": ["172.16.0.2/32"],
            "peers": [
                {
                    "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                    "allowedIPs": ["0.0.0.0/0", "::/0"],
                    "endpoint": endpoint,
                }
            ],
        },
    }
    if mtu:
        ob["settings"]["mtu"] = mtu
    if keep_alive:
        ob["settings"]["peers"][0]["keepAlive"] = keep_alive
    return ob


def make_masque_outbound(tag: str, address: str = "162.159.198.2", port: int = 443) -> dict:
    return {
        "tag": tag,
        "protocol": "masque",
        "settings": {
            "address": address,
            "port": port,
            "privateKey": "masque-priv",
            "publicKey": "masque-pub-pinned",
        },
    }


def make_sample_core_config(optimized: bool = True) -> dict:
    cfg: dict = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "VLESS-IN", "protocol": "vless", "port": 443}],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
            make_wg_outbound("warp1", "162.159.192.1:2408"),
            make_wg_outbound("warp2", "188.114.96.1:500"),
            make_wg_outbound("warp3", "162.159.193.1:1701"),
            make_wg_outbound("warp4", "188.114.97.1:4500"),
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
            ],
        },
    }
    if optimized:
        cfg["api"] = {
            "tag": "API",
            "services": ["HandlerService", "LoggerService", "StatsService", "ObservatoryService"],
        }
        cfg["observatory"] = {
            "subjectSelector": ["warp"],
            "probeURL": rm.DEFAULT_OBSERVATORY_PROBE_URL,
            "probeInterval": "20s",
            "enableConcurrency": True,
        }
    return cfg


class TestHelpersAndState(unittest.TestCase):
    def test_parse_routing_directives(self):
        self.assertEqual(rm.parse_routing_directives(None), [])
        self.assertEqual(rm.parse_routing_directives("VIP customer expires Jan"), [])

        d1 = rm.parse_routing_directives("VIP | node:SG out:warp1 | node : us-1 out : warp-pool")
        self.assertEqual(
            d1,
            [
                {"node": "SG", "outbound": "warp1"},
                {"node": "us-1", "outbound": "warp-pool"},
            ],
        )

    def test_generation_tags_and_prefix_collision(self):
        self.assertEqual(rm.split_generation_tag("warp2"), ("warp2", 0))
        self.assertEqual(rm.split_generation_tag("warp2__r0001"), ("warp2", 1))
        self.assertEqual(rm.split_generation_tag("warp2__r0042"), ("warp2", 42))
        self.assertEqual(rm.format_generation_tag("warp2", 0), "warp2")
        self.assertEqual(rm.format_generation_tag("warp2", 3), "warp2__r0003")

        tags = {"direct", "warp1", "warp2", "warp2__r0001", "warp2__r0002"}
        self.assertFalse(rm.has_prefix_collision("warp1", tags))
        self.assertTrue(rm.has_prefix_collision("warp2", tags))
        self.assertFalse(rm.has_prefix_collision("warp2__r0001", tags))
        self.assertFalse(rm.has_prefix_collision("warp2__r0002", tags))

        # Classic warp1 vs warp10 edge case
        self.assertTrue(rm.has_prefix_collision("warp1", {"warp1", "warp10"}))

    def test_config_v1_compat_and_v2_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "config.json"
            # Write v1 minimal config
            p.write_text(
                json.dumps(
                    {
                        "panel_url": "https://panel.example.com/",
                        "username": "admin",
                        "password": "secret",
                        "poll_interval": 45,
                        "verify_ssl": False,
                    }
                ),
                encoding="utf-8",
            )
            cfg = rm.Config(path=p)
            self.assertTrue(cfg.load())
            self.assertEqual(cfg.panel_url, "https://panel.example.com")
            self.assertTrue(cfg.auto_heal_warp)
            self.assertEqual(cfg.fallback_mode, "warp")
            self.assertEqual(cfg.compact_window, "")

            cfg.fallback_mode = "direct"
            cfg.max_latency_ms = 2200
            cfg.save()

            cfg2 = rm.Config(path=p)
            self.assertTrue(cfg2.load())
            self.assertEqual(cfg2.fallback_mode, "direct")
            self.assertEqual(cfg2.max_latency_ms, 2200)

    def test_state_v1_migration_and_endpoint_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "state.json"
            p.write_text(json.dumps({"1": "abc123hash"}), encoding="utf-8")

            st = rm.StateManager(path=p)
            st.load()
            self.assertEqual(st._hashes, {"1": "abc123hash"})

            used = {rm.WARP_WG_ENDPOINTS[0], rm.WARP_WG_ENDPOINTS[1]}
            ep = st.next_wg_endpoint(used)
            self.assertEqual(ep, rm.WARP_WG_ENDPOINTS[2])
            st.set_active_tag(1, "warp2", "warp2__r0001")
            st.save()

            st2 = rm.StateManager(path=p)
            st2.load()
            self.assertEqual(st2.get_active_tag(1, "warp2"), "warp2__r0001")
            self.assertEqual(st2.endpoint_cursor, 3)


class TestLiveSafetyValidator(unittest.TestCase):
    def test_live_append_outbound_and_replace_routing_is_safe(self):
        before = make_sample_core_config(optimized=True)
        after = copy.deepcopy(before)
        after["outbounds"].append(make_wg_outbound("warp2__r0001", "162.159.195.1:2408"))
        after["routing"]["balancers"] = [
            {"tag": "pg-ha-warp2", "selector": ["warp2__r0001"], "strategy": {"type": "roundRobin"}, "fallbackTag": "warp3"}
        ]
        after["routing"]["rules"].append({"type": "field", "user": ["10"], "balancerTag": "pg-ha-warp2"})

        ok, reason = rm.LiveSafetyValidator.check(before, after)
        self.assertTrue(ok, reason)

    def test_rejects_deleting_or_modifying_wireguard_or_masque(self):
        before = make_sample_core_config(optimized=True)
        before["outbounds"].append(make_masque_outbound("warp5"))

        # 1. Deleting wireguard
        deleted = copy.deepcopy(before)
        deleted["outbounds"] = [ob for ob in deleted["outbounds"] if ob["tag"] != "warp2"]
        ok, reason = rm.LiveSafetyValidator.check(before, deleted)
        self.assertFalse(ok)
        self.assertIn("deleted", reason)

        # 2. In-place editing wireguard endpoint
        edited = copy.deepcopy(before)
        for ob in edited["outbounds"]:
            if ob["tag"] == "warp2":
                ob["settings"]["peers"][0]["endpoint"] = "162.159.195.1:2408"
        ok, reason = rm.LiveSafetyValidator.check(before, edited)
        self.assertFalse(ok)
        self.assertIn("modified in-place", reason)

        # 3. In-place editing masque port
        edited_masque = copy.deepcopy(before)
        for ob in edited_masque["outbounds"]:
            if ob["tag"] == "warp5":
                ob["settings"]["port"] = 8443
        ok, reason = rm.LiveSafetyValidator.check(before, edited_masque)
        self.assertFalse(ok)
        self.assertIn("modified in-place", reason)

        # 4. Modifying observatory (outside live parts)
        obs_changed = copy.deepcopy(before)
        obs_changed["observatory"]["subjectSelector"] = ["warp", "warp2__r0001"]
        ok, reason = rm.LiveSafetyValidator.check(before, obs_changed)
        self.assertFalse(ok)
        self.assertIn("outside outbounds", reason)


class TestWarpHealthManager(unittest.TestCase):
    def setUp(self):
        self.cfg = rm.Config()
        self.cfg.fail_threshold = 2
        self.cfg.refresh_cooldown = 180
        self.cfg.max_latency_ms = 2500
        self.state = rm.StateManager()
        self.mgr = rm.WarpHealthManager(self.cfg, self.state)

    def test_ignores_unprobed_observatory_entries(self):
        obs = [{"node": "sg", "node_id": 1, "alive": False, "delay": 0, "probed": False}]
        degraded, reason = self.mgr.is_tag_degraded(obs)
        self.assertFalse(degraded)
        self.assertEqual(reason, "pending initial probe")

    def test_burst_observatory_entries_count_as_probed(self):
        """Xray burstObservatory always reports last_try_time=0; entries must still be evaluated."""

        class FakeClient:
            def get_node_outbounds_latency(self, node_id, node_name=""):
                return [
                    {"name": "warp1", "alive": False, "delay": 0, "last_try_time": 0, "last_seen_time": 0},
                    {"name": "warp2", "alive": True, "delay": 120, "last_try_time": 0, "last_seen_time": 0},
                ]

        nodes = [{"id": 7, "name": "sg2", "core_config_id": 58, "status": "connected"}]
        burst_cfg = make_sample_core_config(optimized=False)
        burst_cfg["burstObservatory"] = {"subjectSelector": ["warp"], "pingConfig": {"interval": "1m"}}

        tel = self.mgr.poll_core_observatory(FakeClient(), 58, nodes, core_config=burst_cfg)
        self.assertTrue(tel["warp1"][0]["probed"])
        self.assertTrue(self.mgr.is_tag_degraded(tel["warp1"])[0])
        self.assertTrue(tel["warp2"][0]["probed"])
        self.assertFalse(self.mgr.is_tag_degraded(tel["warp2"])[0])

        # Regular observatory: last_try_time=0 + dead stays "pending"; alive+delay counts as probed
        obs_cfg = make_sample_core_config(optimized=True)
        tel2 = self.mgr.poll_core_observatory(FakeClient(), 58, nodes, core_config=obs_cfg)
        self.assertFalse(tel2["warp1"][0]["probed"])
        self.assertTrue(tel2["warp2"][0]["probed"])

    def test_auto_heal_threshold_cooldown_and_generation_reuse(self):
        core_cfg = make_sample_core_config(optimized=True)

        healthy_telemetry = {
            f"warp{i}": [{"node": "sg", "node_id": 1, "alive": True, "delay": 45, "probed": True}]
            for i in range(1, 5)
        }
        dead_warp2 = copy.deepcopy(healthy_telemetry)
        dead_warp2["warp2"] = [{"node": "sg", "node_id": 1, "alive": False, "delay": 0, "probed": True}]

        # Cycle 1: 1st failure (< threshold=2) -> no spawn yet
        out1, act1, chg1 = self.mgr.heal_or_refresh_core(1, "main", core_cfg, dead_warp2)
        self.assertFalse(chg1)
        self.assertEqual(act1["warp2"], "warp2")
        self.assertEqual(self.state.fail_counts["1:warp2"], 1)

        # Cycle 2: 2nd consecutive failure (== threshold=2) -> spawns warp2__r0001 live!
        out2, act2, chg2 = self.mgr.heal_or_refresh_core(1, "main", core_cfg, dead_warp2)
        self.assertTrue(chg2)
        self.assertEqual(act2["warp2"], "warp2__r0001")
        spawned = next(ob for ob in out2 if ob["tag"] == "warp2__r0001")
        self.assertEqual(spawned["settings"]["mtu"], 1280)
        self.assertNotIn("keepAlive", spawned["settings"]["peers"][0])
        # Must pick a fresh endpoint not already used by warp1..warp4
        self.assertNotIn(
            spawned["settings"]["peers"][0]["endpoint"],
            {"162.159.192.1:2408", "188.114.96.1:500", "162.159.193.1:1701", "188.114.97.1:4500"},
        )

        # Update core_cfg with the newly appended outbound
        core_cfg["outbounds"] = out2

        # Cycle 3: Immediate failure during cooldown -> blocked by refresh_cooldown
        dead_r1 = copy.deepcopy(healthy_telemetry)
        dead_r1["warp2"] = [{"node": "sg", "node_id": 1, "alive": True, "delay": 38, "probed": True}]
        dead_r1["warp2__r0001"] = [{"node": "sg", "node_id": 1, "alive": False, "delay": 0, "probed": True}]
        self.mgr.heal_or_refresh_core(1, "main", core_cfg, dead_r1)
        _, act_cd, chg_cd = self.mgr.heal_or_refresh_core(1, "main", core_cfg, dead_r1)
        self.assertFalse(chg_cd)
        self.assertEqual(act_cd["warp2"], "warp2__r0001")

        # Expire cooldown -> warp2 (gen 0) is healthy again! Should REUSE warp2 with 0 new outbounds!
        self.state.last_refresh_ts["1:warp2"] -= 300
        out_reused, act_reused, chg_reused = self.mgr.heal_or_refresh_core(1, "main", core_cfg, dead_r1)
        self.assertTrue(chg_reused)
        self.assertEqual(act_reused["warp2"], "warp2")
        self.assertEqual(len(out_reused), len(out2), "Must reuse recovered warp2 without adding new outbound")

        # Verify balancer prefix-collision guard when warp2 AND warp2__r0001 coexist while warp2 is active:
        bals, slot_bal_map = self.mgr.build_managed_balancers(core_cfg, out_reused, act_reused, telemetry=dead_r1)
        self.assertNotIn("warp2", slot_bal_map, "Prefix-colliding base tag must bypass prefix balancer")
        self.assertIn("warp1", slot_bal_map)
        # Sibling fallback for warp1 should skip degraded/colliding slots if needed and always use outboundTag
        bal_w1 = next(b for b in bals if b["tag"] == "pg-ha-warp1")
        self.assertFalse(bal_w1["fallbackTag"].startswith("pg-ha-"))

    def test_refresh_avoids_unreachable_cloudflare_block(self):
        """Reproduces Singapore-1: 16 slots, every 162.159.193.x endpoint dead from the node."""
        core_cfg = make_sample_core_config(optimized=True)
        core_cfg["outbounds"] = [{"tag": "direct", "protocol": "freedom", "settings": {}}] + [
            make_wg_outbound(f"warp{i + 1}", rm.WARP_WG_ENDPOINTS[i]) for i in range(16)
        ]
        self.state.endpoint_cursor = 16

        telemetry = {}
        dead_tags = set()
        for i in range(16):
            tag = f"warp{i + 1}"
            dead = rm.WARP_WG_ENDPOINTS[i].startswith("162.159.193.")
            if dead:
                dead_tags.add(tag)
            telemetry[tag] = [{"node": "sg", "node_id": 1, "alive": not dead, "delay": 0 if dead else 21, "probed": True}]
        self.assertEqual(dead_tags, {"warp3", "warp9", "warp15"})

        self.assertEqual(
            self.mgr.find_unreachable_prefixes(core_cfg["outbounds"], telemetry),
            {"162.159.193.0/24"},
        )

        out, act, chg = self.mgr.heal_or_refresh_core(
            2, "Singapore-1", core_cfg, telemetry, manual_refresh_targets={"warp3", "warp9", "warp15"}
        )
        self.assertTrue(chg)
        old_eps = set(rm.WARP_WG_ENDPOINTS[:16])
        new_eps = []
        for base in ("warp3", "warp9", "warp15"):
            self.assertEqual(act[base], f"{base}__r0001")
            ob = next(o for o in out if o["tag"] == f"{base}__r0001")
            ep = ob["settings"]["peers"][0]["endpoint"]
            self.assertFalse(ep.startswith("162.159.193."), f"{base} got unreachable endpoint {ep}")
            self.assertNotIn(ep, old_eps)
            new_eps.append(ep)
        self.assertEqual(len(set(new_eps)), 3, "Each refreshed slot must get a distinct endpoint")

    def test_masque_live_spawn_preserves_ip_rotates_port_and_cleans_partial_xmux(self):
        core_cfg = make_sample_core_config(optimized=True)
        masque_ob = make_masque_outbound("warp1", "162.159.198.2", 443)
        # Simulate legacy partial xmux that breaks Xray defaultMasqueXmux()
        masque_ob["streamSettings"] = {
            "network": "masque",
            "security": "tls",
            "masqueSettings": {"xmux": {"hMaxReusableSecs": "900-1800"}},
        }
        core_cfg["outbounds"] = [
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            masque_ob,
        ]
        out, act, chg = self.mgr.heal_or_refresh_core(
            1, "masque-core", core_cfg, telemetry={}, manual_refresh_targets={"warp1"}
        )
        self.assertTrue(chg)
        self.assertEqual(act["warp1"], "warp1__r0001")
        spawned = next(ob for ob in out if ob["tag"] == "warp1__r0001")
        self.assertEqual(spawned["settings"]["address"], "162.159.198.2")
        self.assertNotEqual(spawned["settings"]["port"], 443)
        self.assertNotIn("xmux", spawned["streamSettings"]["masqueSettings"])

    def test_optimize_and_compact_core_config(self):
        raw_cfg = make_sample_core_config(optimized=False)
        # Simulate unoptimized WARP outbounds sharing engage.cloudflareclient.com:2408 without mtu/keepAlive
        for ob in raw_cfg["outbounds"]:
            if ob["tag"].startswith("warp"):
                ob["settings"].pop("mtu", None)
                ob["settings"]["peers"][0].pop("keepAlive", None)
                ob["settings"]["peers"][0]["endpoint"] = "engage.cloudflareclient.com:2408"

        opt_cfg, notes = self.mgr.optimize_core_config(1, raw_cfg)
        self.assertTrue(notes)
        self.assertIn("ObservatoryService", opt_cfg["api"]["services"])
        self.assertEqual(opt_cfg["observatory"]["subjectSelector"], ["warp"])
        self.assertTrue(opt_cfg["observatory"]["enableConcurrency"])

        warp_eps = set()
        for ob in opt_cfg["outbounds"]:
            if ob["tag"].startswith("warp"):
                self.assertEqual(ob["settings"]["mtu"], 1280)
                self.assertEqual(ob["settings"]["peers"][0]["keepAlive"], 20)
                ep = ob["settings"]["peers"][0]["endpoint"]
                self.assertNotIn("engage.cloudflareclient.com", ep)
                warp_eps.add(ep)
        self.assertEqual(len(warp_eps), 4, "All 4 WARP slots must get distinct Anycast endpoints")

        # Simulate two live spawns on warp2, then run compact_core_config
        out, _, _ = self.mgr.heal_or_refresh_core(
            1, "main", opt_cfg, {}, manual_refresh_targets={"warp2"}, force_spawn=True
        )
        opt_cfg["outbounds"] = out
        out, _, _ = self.mgr.heal_or_refresh_core(
            1, "main", opt_cfg, {}, manual_refresh_targets={"warp2"}, force_spawn=True
        )
        opt_cfg["outbounds"] = out
        r2_ep = next(ob for ob in out if ob["tag"] == "warp2__r0002")["settings"]["peers"][0]["endpoint"]

        compacted, cnotes = self.mgr.compact_core_config(1, opt_cfg)
        self.assertTrue(cnotes)
        tags_after = [ob["tag"] for ob in compacted["outbounds"]]
        self.assertEqual(tags_after, ["direct", "block", "warp1", "warp2", "warp3", "warp4"])
        w2_after = next(ob for ob in compacted["outbounds"] if ob["tag"] == "warp2")
        self.assertEqual(w2_after["settings"]["peers"][0]["endpoint"], r2_ep)
        self.assertEqual(w2_after["settings"]["peers"][0]["keepAlive"], 20)

        # Verify optimize_core_config strips partial MASQUE xmux bug
        masque_bad = make_masque_outbound("warp9", "162.159.198.2", 443)
        masque_bad["streamSettings"] = {
            "network": "masque",
            "security": "tls",
            "masqueSettings": {"xmux": {"hMaxReusableSecs": "900-1800"}},
        }
        compacted["outbounds"].append(masque_bad)
        fixed_cfg, fixed_notes = self.mgr.optimize_core_config(1, compacted)
        self.assertTrue(any("partial MASQUE xmux" in n for n in fixed_notes))
        w9_after = next(ob for ob in fixed_cfg["outbounds"] if ob["tag"] == "warp9")
        self.assertNotIn("xmux", w9_after["streamSettings"]["masqueSettings"])


class TestEndToEndRouteSync(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.cfg = rm.Config(path=Path(self.tmpdir.name) / "config.json")
        self.cfg.panel_url = "https://panel.local"
        self.cfg.username = "admin"
        self.cfg.password = "pass"
        self.cfg.fail_threshold = 1  # Trigger heal on 1st dead poll for concise e2e test
        self.state = rm.StateManager(path=Path(self.tmpdir.name) / "state.json")

        self.core_doc = {
            "id": 1,
            "name": "main-xray",
            "type": "xray",
            "config": make_sample_core_config(optimized=True),
            "exclude_inbound_tags": ["API_IN"],
            "fallbacks_inbound_tags": [],
        }
        self.users_doc = [
            {"id": 101, "username": "alice", "note": "node:sg out:warp1"},
            {"id": 102, "username": "bob", "note": "node:sg out:warp2"},
            {"id": 103, "username": "carol", "note": "node:sg out:warp-pool"},
            {"id": 104, "username": "dave", "note": "node:sg out:direct"},
        ]
        self.nodes_doc = [
            {"id": 10, "name": "sg", "core_config_id": 1, "status": "connected"},
        ]
        self.latencies_doc = [
            {"name": "warp1", "alive": True, "delay": 32, "last_try_time": 1700000000},
            {"name": "warp2", "alive": False, "delay": 0, "last_try_time": 1700000000},
            {"name": "warp3", "alive": True, "delay": 40, "last_try_time": 1700000000},
            {"name": "warp4", "alive": True, "delay": 44, "last_try_time": 1700000000},
        ]
        self.put_calls: list[dict] = []
        self.fail_put = False

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/api/admin/token" and request.method == "POST":
                return httpx.Response(200, json={"access_token": "tok-123"})
            if path == "/api/users" and request.method == "GET":
                return httpx.Response(200, json={"users": self.users_doc, "total": len(self.users_doc)})
            if path == "/api/nodes" and request.method == "GET":
                return httpx.Response(200, json={"nodes": self.nodes_doc})
            if path == "/api/cores" and request.method == "GET":
                return httpx.Response(200, json={"cores": [self.core_doc]})
            if path == "/api/core/1" and request.method == "GET":
                return httpx.Response(200, json=self.core_doc)
            if path == "/api/node/10/outbounds_latency" and request.method == "GET":
                return httpx.Response(200, json={"latencies": self.latencies_doc})
            if path == "/api/core/1" and request.method == "PUT":
                if self.fail_put:
                    return httpx.Response(502, text="Bad Gateway")
                body = json.loads(request.content.decode("utf-8"))
                self.put_calls.append(
                    {"params": dict(request.url.params), "body": body}
                )
                self.core_doc["config"] = body["config"]
                return httpx.Response(200, json=self.core_doc)
            return httpx.Response(404, text=f"Unhandled {request.method} {path}")

        self.client = rm.PanelClient(self.cfg)
        self.client._client.close()
        self.client._client = httpx.Client(
            base_url=self.cfg.panel_url,
            transport=httpx.MockTransport(handler),
        )

    def tearDown(self):
        self.client.close()
        self.tmpdir.cleanup()

    def test_dry_run_does_not_mutate_state_or_push(self):
        syncer = rm.RouteSync(self.client, self.state, config=self.cfg, dry_run=True)
        updates = syncer.sync()
        self.assertEqual(updates, 0)
        self.assertEqual(len(self.put_calls), 0)
        self.assertIsNone(self.state.get_active_tag(1, "warp2"))
        self.assertEqual(self.state.last_refresh_ts, {})

    def test_transient_put_failure_rolls_back_state_for_immediate_retry(self):
        self.fail_put = True
        syncer = rm.RouteSync(self.client, self.state, config=self.cfg, dry_run=False)
        updates = syncer.sync()
        self.assertEqual(updates, 0)
        # Must NOT have locked warp2 into refresh_cooldown after a failed PUT!
        self.assertNotIn("1:warp2", self.state.last_refresh_ts)

        # Next cycle when Panel recovers succeeds immediately!
        self.fail_put = False
        updates2 = syncer.sync()
        self.assertEqual(updates2, 1)
        self.assertEqual(self.state.get_active_tag(1, "warp2"), "warp2__r0001")

    def test_full_live_heal_and_routing_sync(self):
        before_cfg = copy.deepcopy(self.core_doc["config"])
        syncer = rm.RouteSync(self.client, self.state, config=self.cfg, dry_run=False)
        updates = syncer.sync()
        self.assertEqual(updates, 1)
        self.assertEqual(len(self.put_calls), 1)
        self.assertEqual(self.put_calls[0]["params"].get("restart_nodes"), "true")

        pushed_cfg = self.put_calls[0]["body"]["config"]
        # Guarantee live-update safety invariant holds on pushed config!
        is_safe, reason = rm.LiveSafetyValidator.check(before_cfg, pushed_cfg)
        self.assertTrue(is_safe, reason)

        # Verify warp2__r0001 was appended without removing warp2
        out_tags = [ob["tag"] for ob in pushed_cfg["outbounds"]]
        self.assertIn("warp2", out_tags)
        self.assertIn("warp2__r0001", out_tags)

        # Verify user routing rules preserve private-IP block rule + use balancerTag/outboundTag properly
        rules = pushed_cfg["routing"]["rules"]
        self.assertEqual(rules[0], {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"})
        user_rules = {
            (r.get("balancerTag") or r.get("outboundTag")): r
            for r in rules
            if "user" in r
        }
        self.assertEqual(user_rules["pg-ha-warp1"]["balancerTag"], "pg-ha-warp1")
        self.assertEqual(user_rules["pg-ha-warp1"]["user"], ["101"])
        self.assertEqual(user_rules["pg-ha-warp2"]["balancerTag"], "pg-ha-warp2")
        self.assertEqual(user_rules["pg-ha-warp2"]["user"], ["102"])
        self.assertEqual(user_rules["warp-pool"]["balancerTag"], "warp-pool")
        self.assertEqual(user_rules["warp-pool"]["user"], ["103"])
        self.assertEqual(user_rules["direct"]["outboundTag"], "direct")
        self.assertEqual(user_rules["direct"]["user"], ["104"])

        # Verify pg-ha-warp2 points to the fresh warp2__r0001 tunnel!
        bal_w2 = next(b for b in pushed_cfg["routing"]["balancers"] if b["tag"] == "pg-ha-warp2")
        self.assertEqual(bal_w2["selector"], ["warp2__r0001"])
        self.assertEqual(bal_w2["fallbackTag"], "warp3")


class TestCryptoAndWarpRegistrar(unittest.TestCase):
    def test_x25519_rfc7748_and_pure_python_keygen(self):
        # RFC 7748 Section 5.2 test vector (scalar * basepoint u=9)
        scalar = bytes.fromhex(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
        )
        expected = bytes.fromhex(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        )
        # RFC vector uses an explicit arbitrary u-coordinate in sec 5.2; verify 6.1 basepoint too
        alice_priv = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        )
        alice_pub_expected = bytes.fromhex(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        )
        self.assertEqual(rm._x25519_scalar_mult(alice_priv), alice_pub_expected)
        self.assertEqual(len(scalar), 32)
        self.assertEqual(len(expected), 32)

        priv_b64, pub_b64 = rm.generate_wireguard_keypair(prefer_cryptography=False)
        import base64 as _b64
        self.assertEqual(len(_b64.b64decode(priv_b64)), 32)
        self.assertEqual(len(_b64.b64decode(pub_b64)), 32)
        self.assertNotEqual(priv_b64, pub_b64)

    def test_ec_p256_der_and_pem_generation(self):
        import base64 as _b64
        pkcs8_pem, spki_b64 = rm.generate_ec_p256_keypair(prefer_cryptography=False)
        self.assertTrue(pkcs8_pem.startswith("-----BEGIN PRIVATE KEY-----\n"))
        self.assertTrue(pkcs8_pem.rstrip().endswith("-----END PRIVATE KEY-----"))

        spki_der = _b64.b64decode(spki_b64)
        self.assertEqual(len(spki_der), 91)
        self.assertTrue(spki_der.startswith(rm._P256_SPKI_PREFIX))
        self.assertEqual(spki_der[len(rm._P256_SPKI_PREFIX)], 0x04)

        b64_lines = "".join(
            line for line in pkcs8_pem.splitlines()
            if not line.startswith("-----")
        )
        pkcs8_der = _b64.b64decode(b64_lines)
        self.assertEqual(len(pkcs8_der), 138)

    def test_register_masque_matches_3xui_api_and_builds_clean_outbound(self):
        seen_calls: list[dict] = []

        def cf_handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content.decode("utf-8")) if request.content else None
            seen_calls.append({
                "method": request.method,
                "url": str(request.url),
                "headers": dict(request.headers),
                "body": body,
            })
            if request.method == "POST" and request.url.path == "/v0a4471/reg":
                return httpx.Response(200, json={"id": "dev-masque-1", "token": "tok-m1"})
            if request.method == "PUT" and request.url.path == "/v0a4471/reg/dev-masque-1/account":
                return httpx.Response(200, json={"license": body["license"]})
            if request.method == "GET" and request.url.path == "/v0a4471/reg/dev-masque-1":
                return httpx.Response(200, json={"id": "dev-masque-1"})
            if request.method == "PATCH" and request.url.path == "/v0a4471/reg/dev-masque-1":
                if body.get("tunnel_type") == "masque":
                    return httpx.Response(200, json={
                        "id": "dev-masque-1",
                        "warp_enabled": False,
                        "config": {},
                    })
                if body.get("warp_enabled") is True:
                    return httpx.Response(200, json={
                        "id": "dev-masque-1",
                        "warp_enabled": True,
                        "config": {
                            "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110::2"}},
                            "peers": [{
                                "public_key": "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n",
                                "endpoint": {"v4": "162.159.198.1:0"},
                            }],
                        },
                    })
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(cf_handler))
        try:
            registrar = rm.WarpRegistrar(http_client=client)
            rec = registrar.register_masque(license_key="LIC-1234")
        finally:
            client.close()

        self.assertEqual([c["method"] for c in seen_calls], ["POST", "PUT", "GET", "PATCH", "PATCH"])
        patch_enroll = seen_calls[3]
        self.assertEqual(patch_enroll["headers"].get("cf-client-version"), rm.CF_WARP_MASQUE_CLIENT_VER)
        self.assertEqual(patch_enroll["body"]["key_type"], "secp256r1")
        self.assertEqual(patch_enroll["body"]["tunnel_type"], "masque")

        ob = registrar.build_masque_outbound("warp15__r0001", rec, port=443, alpn=["h3"])
        self.assertEqual(ob["protocol"], "masque")
        self.assertEqual(ob["settings"], {"address": "162.159.198.1", "port": 443})
        self.assertEqual(ob["streamSettings"]["tlsSettings"]["serverName"], rm.CF_WARP_MASQUE_SNI)
        self.assertEqual(ob["streamSettings"]["tlsSettings"]["alpn"], ["h3"])
        self.assertEqual(ob["streamSettings"]["masqueSettings"]["warp"]["address"], ["172.16.0.2/32", "2606:4700:110::2/128"])
        self.assertNotIn("xmux", ob["streamSettings"]["masqueSettings"])

    def test_register_wireguard_and_rate_limit(self):
        import base64 as _b64
        cid_b64 = _b64.b64encode(bytes([12, 34, 56])).decode("ascii")

        def wg_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v0a4005/reg":
                return httpx.Response(200, json={
                    "id": "dev-wg-1",
                    "token": "tok-wg",
                    "config": {
                        "client_id": cid_b64,
                        "interface": {"addresses": {"v4": "172.16.0.5", "v6": "fd01::5"}},
                        "peers": [{
                            "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                            "endpoint": {"v4": "162.159.192.1:0"},
                        }],
                    },
                })
            return httpx.Response(429, headers={"Retry-After": "120"})

        client = httpx.Client(transport=httpx.MockTransport(wg_handler))
        try:
            registrar = rm.WarpRegistrar(http_client=client)
            rec = registrar.register_wireguard()
            self.assertEqual(rec["reserved"], [12, 34, 56])
            ob = registrar.build_wireguard_outbound("warp1__r0001", rec, endpoint="188.114.96.1:500", keepalive=0)
            self.assertEqual(ob["settings"]["reserved"], [12, 34, 56])
            self.assertTrue(ob["settings"]["noKernelTun"])
            self.assertEqual(ob["streamSettings"]["sockopt"]["domainStrategy"], "ForceIPv4v6")
            self.assertNotIn("keepAlive", ob["settings"]["peers"][0])
        finally:
            client.close()

        client429 = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(429, headers={"Retry-After": "95"})))
        try:
            with self.assertRaises(rm.WarpRateLimitError) as ctx:
                rm.WarpRegistrar(http_client=client429).register_masque()
            self.assertEqual(ctx.exception.retry_after_sec, 95)
        finally:
            client429.close()

        state = rm.StateManager(path=Path(tempfile.gettempdir()) / "nonexistent-rate-state.json")
        state.record_registration(now=1000.0)
        state.record_registration(now=1010.0)
        allowed, wait_sec = state.can_register(max_per_hour=2, now=1020.0)
        self.assertFalse(allowed)
        self.assertGreater(wait_sec, 3500)


class TestMasqueMigrationAndWireGuardAging(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.cfg = rm.Config(path=Path(self.tmpdir.name) / "config.json")
        self.cfg.panel_url = "https://panel.local"
        self.cfg.username = "admin"
        self.cfg.password = "pass"
        self.cfg.fail_threshold = 1
        self.cfg.refresh_cooldown = 180
        self.cfg.identity_escalate_window = 1800
        self.cfg.latency_degrade_factor = 3.0
        self.state = rm.StateManager(path=Path(self.tmpdir.name) / "state.json")
        self.device_store = rm.WarpDeviceStore(path=Path(self.tmpdir.name) / "warp_devices.json")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_latency_baseline_slow_slot_detection_and_identity_escalation(self):
        core_cfg = make_sample_core_config(optimized=True)
        mgr = rm.WarpHealthManager(self.cfg, self.state)

        # Record 3 healthy samples (~20ms) for warp2
        healthy = {
            f"warp{i}": [{"node": "sg", "node_id": 1, "alive": True, "delay": 20, "probed": True}]
            for i in range(1, 5)
        }
        for _ in range(3):
            _, _, chg = mgr.heal_or_refresh_core(1, "main", core_cfg, healthy)
            self.assertFalse(chg)
        self.assertEqual(self.state.get_latency_baseline(1, "warp2"), 20.0)

        # Latency spike to 400ms (> max(250, 20*3)) -> still alive=True, but triggers slow-slot heal!
        slow_w2 = copy.deepcopy(healthy)
        slow_w2["warp2"] = [{"node": "sg", "node_id": 1, "alive": True, "delay": 400, "probed": True}]
        out1, act1, chg1 = mgr.heal_or_refresh_core(1, "main", core_cfg, slow_w2)
        self.assertTrue(chg1)
        self.assertEqual(act1["warp2"], "warp2__r0001")
        self.assertEqual(self.state.last_rotation_mode["1:warp2"], "endpoint")

        # Now simulate warp2__r0001 stalling 300s later (past cooldown=180s, within escalate_window=1800s)
        core_cfg["outbounds"] = out1
        self.state.last_refresh_ts["1:warp2"] -= 300

        def cf_wg(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "id": "dev-fresh-2",
                "token": "tok-f2",
                "config": {
                    "client_id": "AQID",
                    "interface": {"addresses": {"v4": "172.16.9.9", "v6": "fd01::9"}},
                    "peers": [{"public_key": "PEERPUB", "endpoint": {"v4": "162.159.195.6:0"}}],
                },
            })

        cf_client = httpx.Client(transport=httpx.MockTransport(cf_wg))
        try:
            registrar = rm.WarpRegistrar(http_client=cf_client)
            dead_r1 = copy.deepcopy(healthy)
            # Old warp2 stays slow while warp2__r0001 stalls -> forces fresh identity escalation!
            dead_r1["warp2"] = [{"node": "sg", "node_id": 1, "alive": True, "delay": 400, "probed": True}]
            dead_r1["warp2__r0001"] = [{"node": "sg", "node_id": 1, "alive": False, "delay": 0, "probed": True}]
            out2, act2, chg2 = mgr.heal_or_refresh_core(
                1, "main", core_cfg, dead_r1,
                force_spawn=False,
                registrar=registrar,
                device_store=self.device_store,
            )
        finally:
            cf_client.close()

        self.assertTrue(chg2)
        self.assertEqual(act2["warp2"], "warp2__r0002")
        self.assertEqual(self.state.last_rotation_mode["1:warp2"], "identity")
        spawned2 = next(o for o in out2 if o["tag"] == "warp2__r0002")
        self.assertNotEqual(spawned2["settings"]["secretKey"], "privkey-warp2")
        self.assertIsNotNone(self.device_store.get(1, "warp2"))

    def test_scheduled_identity_max_age_hours(self):
        self.cfg.identity_max_age_hours = 12.0
        core_cfg = make_sample_core_config(optimized=True)
        mgr = rm.WarpHealthManager(self.cfg, self.state)

        # Seed warp1 age at 13 hours ago, others fresh
        import time as _time
        now = _time.time()
        self.state.identity_created_ts["1:warp1"] = now - (13.0 * 3600.0)
        for slot in ("warp2", "warp3", "warp4"):
            self.state.identity_created_ts[f"1:{slot}"] = now

        cf_client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json={
            "id": "dev-age-1",
            "token": "tok-a1",
            "config": {
                "client_id": "AQID",
                "interface": {"addresses": {"v4": "172.16.8.8"}},
                "peers": [{"public_key": "PEER", "endpoint": {"v4": "162.159.192.7:0"}}],
            },
        })))
        try:
            registrar = rm.WarpRegistrar(http_client=cf_client)
            _, act, chg = mgr.heal_or_refresh_core(
                1, "main", core_cfg, telemetry={}, registrar=registrar, device_store=self.device_store
            )
        finally:
            cf_client.close()

        self.assertTrue(chg)
        self.assertEqual(act["warp1"], "warp1__r0001")
        self.assertEqual(act["warp2"], "warp2")

    def test_diagnose_and_migrate_masque_flows(self):
        core_doc = {
            "id": 1,
            "name": "main-xray",
            "type": "xray",
            "config": make_sample_core_config(optimized=True),
            "exclude_inbound_tags": [],
            "fallbacks_inbound_tags": [],
        }
        # Clone warp1's secretKey onto warp2 to test duplicate identity audit
        core_doc["config"]["outbounds"][3]["settings"]["secretKey"] = (
            core_doc["config"]["outbounds"][2]["settings"]["secretKey"]
        )
        nodes_doc = [
            {"id": 10, "name": "sg", "core_config_id": 1, "status": "connected", "xray_version": "26.9.30"},
        ]
        users_doc = [{"id": 101, "username": "alice", "note": "node:sg out:warp1"}]
        latencies_doc = [
            {"name": "warp1", "alive": True, "delay": 25, "last_try_time": 1700000000},
            {"name": "warp2", "alive": True, "delay": 30, "last_try_time": 1700000000},
            {"name": "warp3", "alive": True, "delay": 28, "last_try_time": 1700000000},
            {"name": "warp4", "alive": True, "delay": 31, "last_try_time": 1700000000},
        ]
        puts: list[dict] = []

        def panel_handler(request: httpx.Request) -> httpx.Response:
            p = request.url.path
            if p == "/api/admin/token":
                return httpx.Response(200, json={"access_token": "tok"})
            if p == "/api/users":
                return httpx.Response(200, json={"users": users_doc, "total": len(users_doc)})
            if p == "/api/nodes":
                return httpx.Response(200, json={"nodes": nodes_doc})
            if p == "/api/cores":
                return httpx.Response(200, json={"cores": [core_doc]})
            if p == "/api/core/1" and request.method == "GET":
                return httpx.Response(200, json=core_doc)
            if p == "/api/node/10/outbounds_latency":
                return httpx.Response(200, json={"latencies": latencies_doc})
            if p == "/api/core/1" and request.method == "PUT":
                body = json.loads(request.content.decode("utf-8"))
                puts.append(body)
                core_doc["config"] = body["config"]
                return httpx.Response(200, json=core_doc)
            return httpx.Response(404)

        client = rm.PanelClient(self.cfg)
        client._client.close()
        client._client = httpx.Client(base_url=self.cfg.panel_url, transport=httpx.MockTransport(panel_handler))

        cf_calls = 0

        def cf_masque_handler(request: httpx.Request) -> httpx.Response:
            nonlocal cf_calls
            cf_calls += 1
            if request.method == "POST":
                return httpx.Response(200, json={"id": f"m-{cf_calls}", "token": f"t-{cf_calls}"})
            return httpx.Response(200, json={
                "id": f"m-{cf_calls}",
                "warp_enabled": True,
                "config": {
                    "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700::2"}},
                    "peers": [{"public_key": "MASQUE_PUB", "endpoint": {"v4": "162.159.198.2:0"}}],
                },
            })

        cf_client = httpx.Client(transport=httpx.MockTransport(cf_masque_handler))
        try:
            registrar = rm.WarpRegistrar(http_client=cf_client)
            syncer = rm.RouteSync(
                client, self.state, config=self.cfg, dry_run=False,
                device_store=self.device_store, registrar=registrar,
            )

            # 1. --diagnose flags duplicate secretKey AND old xray_version
            diag = syncer.diagnose()
            rep = diag["cores"][0]
            self.assertFalse(rep["masque_ready"])
            self.assertIn("26.9.30", rep["masque_blockers"][0])
            self.assertEqual(len(rep["duplicate_keys"]), 1)

            # 2. --migrate-masque MUST refuse when node Xray < 26.10.21
            self.assertEqual(syncer.migrate_to_masque("warp1"), 0)
            self.assertEqual(cf_calls, 0)
            self.assertEqual(len(puts), 0)

            # Upgrade node Xray version >= 26.10.21
            nodes_doc[0]["xray_version"] = "26.11.9"

            # 3. Probe stays DEAD for warp2 -> Stage A adds warp2__r0001, Stage B MUST NOT switch routing!
            latencies_doc.append({"name": "warp2__r0001", "alive": False, "delay": 0, "last_try_time": 1700000010})
            self.assertEqual(syncer.migrate_to_masque("warp2", probe_timeout=1, wait_probe=True), 0)
            self.assertEqual(len(puts), 1, "Only Stage A AddOutbound should have executed")
            self.assertNotEqual(self.state.get_active_tag(1, "warp2"), "warp2__r0001")

            # 4. Probe OK for warp1 -> Stage A + Stage B execute live with 0 Xray restarts!
            puts_before = len(puts)
            latencies_doc.append({"name": "warp1__r0001", "alive": True, "delay": 18, "last_try_time": 1700000020})
            migrated = syncer.migrate_to_masque("warp1", probe_timeout=2, wait_probe=True)
            self.assertEqual(migrated, 1)
            self.assertEqual(len(puts) - puts_before, 2, "Expected Stage A (AddOutbound) + Stage B (ReplaceRouting)")

            stage_b_cfg = puts[-1]["config"]
            new_ob = next(o for o in stage_b_cfg["outbounds"] if o["tag"] == "warp1__r0001")
            self.assertEqual(new_ob["protocol"], "masque")
            self.assertNotIn("xmux", new_ob["streamSettings"]["masqueSettings"])
            bal_w1 = next(b for b in stage_b_cfg["routing"]["balancers"] if b["tag"] == "pg-ha-warp1")
            self.assertEqual(bal_w1["selector"], ["warp1__r0001"])
            self.assertIsNotNone(self.device_store.get(1, "warp1"))

            # 5. Daemon process with stale in-memory state MUST reload disk state updated by CLI
            daemon_state = rm.StateManager(path=self.state.path)
            daemon_state.active_generations = {"1": {"warp1": "warp1"}}
            daemon_state._loaded_sig = None  # simulates pre-migration load in long-running daemon
            daemon_syncer = rm.RouteSync(client, daemon_state, config=self.cfg, dry_run=False)
            daemon_updates = daemon_syncer.sync()
            self.assertEqual(daemon_state.get_active_tag(1, "warp1"), "warp1__r0001")
            bal_w1_after = next(b for b in core_doc["config"]["routing"]["balancers"] if b["tag"] == "pg-ha-warp1")
            self.assertEqual(bal_w1_after["selector"], ["warp1__r0001"])
            self.assertEqual(daemon_updates, 0, "Daemon should see already-synced MASQUE state and make 0 PUTs")

            # 6. Once previously-staged warp2__r0001 recovers OK, re-running --migrate-masque promotes it with 0 CF calls!
            latencies_doc[-2]["alive"] = True
            latencies_doc[-2]["delay"] = 22
            cf_before = cf_calls
            promoted = syncer.migrate_to_masque("warp2", probe_timeout=1, wait_probe=True)
            self.assertEqual(promoted, 1)
            self.assertEqual(cf_calls, cf_before, "Must adopt healthy pre-staged MASQUE outbound with 0 Cloudflare calls")
            self.assertEqual(self.state.get_active_tag(1, "warp2"), "warp2__r0001")
        finally:
            cf_client.close()
            client.close()


if __name__ == "__main__":
    unittest.main()


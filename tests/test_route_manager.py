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
        self.assertEqual(spawned["settings"]["peers"][0]["keepAlive"], 20)
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

    def test_masque_live_spawn_preserves_ip_and_rotates_port(self):
        core_cfg = make_sample_core_config(optimized=True)
        core_cfg["outbounds"] = [
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            make_masque_outbound("warp1", "162.159.198.2", 443),
        ]
        out, act, chg = self.mgr.heal_or_refresh_core(
            1, "masque-core", core_cfg, telemetry={}, manual_refresh_targets={"warp1"}
        )
        self.assertTrue(chg)
        self.assertEqual(act["warp1"], "warp1__r0001")
        spawned = next(ob for ob in out if ob["tag"] == "warp1__r0001")
        self.assertEqual(spawned["settings"]["address"], "162.159.198.2")
        self.assertNotEqual(spawned["settings"]["port"], 443)
        self.assertEqual(
            spawned["streamSettings"]["masqueSettings"]["xmux"]["hMaxReusableSecs"],
            "900-1800",
        )

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


if __name__ == "__main__":
    unittest.main()


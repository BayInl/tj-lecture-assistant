import json
import os
import sys
import tempfile
import unittest

# Test against an isolated temporary TJ_DATA_DIR so local server/tj_config.json is never touched.
_TMP_DIR = tempfile.TemporaryDirectory(prefix="tj_srv_test_")
os.environ["TJ_DATA_DIR"] = _TMP_DIR.name
os.environ["TJ_BOOTSTRAP_API_TOKEN"] = "boot-admin-token-123456"
os.environ["TJ_BOOTSTRAP_USER"] = "admin"
os.environ["TJ_BOOTSTRAP_PASSWORD"] = "adminpass123"

SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)

import lecture_grabber as g
import dida365 as dida_mod
import server_app as srv


class MultiUserServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg = srv.load_cfg()
        auth = cfg.setdefault("auth", {})
        auth["enabled"] = True
        auth["username"] = "admin"
        auth["password_hash"] = srv._hash_password("adminpass123")
        auth["api_token"] = "boot-admin-token-123456"
        auth["session_secret"] = "test-secret-0123456789abcdef0123456789abcdef"
        auth["session_version"] = 1
        srv.save_cfg(cfg)
        srv._init_all_users()
        cls.app = srv.app
        cls.app.testing = True

    def test_client_session_isolation(self):
        c1 = g.TongjiClient(cookie="PG.ASP.Session.ID=user1")
        c2 = g.TongjiClient(cookie="PG.ASP.Session.ID=user2")
        self.assertNotEqual(c1._hdr_json()["Cookie"], c2._hdr_json()["Cookie"])
        self.assertIsNot(c1._session, c2._session)

    def test_multi_user_isolation_and_auth(self):
        cli_admin = self.app.test_client()
        cli_anon = self.app.test_client()

        # Unauthenticated status rejected
        r0 = cli_anon.get("/api/status")
        self.assertEqual(r0.status_code, 401)

        # Admin login
        r_login = cli_admin.post("/api/login", json={"username": "admin", "password": "adminpass123"})
        self.assertEqual(r_login.status_code, 200)
        r_st = cli_admin.get("/api/status")
        self.assertEqual(r_st.status_code, 200)
        d_st = r_st.get_json()
        self.assertEqual(d_st["user"]["username"], "admin")
        self.assertEqual(d_st["user"]["role"], "admin")

        # Registration closed by default
        r_reg_closed = cli_anon.post("/api/register", json={"username": "alice", "password": "password123"})
        self.assertEqual(r_reg_closed.status_code, 403)

        # Admin enables invite-code registration and creates alice
        self.assertEqual(
            cli_admin.post("/api/admin/users", json={"action": "settings", "allow_register": True, "invite_code": "TJ2026"}).status_code,
            200,
        )
        r_create = cli_admin.post("/api/admin/users", json={"action": "create", "username": "alice", "password": "alicepass1"})
        self.assertEqual(r_create.status_code, 200)
        alice_tok = r_create.get_json()["api_token"]
        self.assertTrue(alice_tok)

        # Wrong invite code rejected; valid invite code registers bob
        r_bad_inv = cli_anon.post("/api/register", json={"username": "bob", "password": "bobpass123", "invite_code": "WRONG"})
        self.assertEqual(r_bad_inv.status_code, 403)

        cli_bob = self.app.test_client()
        r_bob_reg = cli_bob.post("/api/register", json={"username": "bob", "password": "bobpass123", "invite_code": "TJ2026"})
        self.assertEqual(r_bob_reg.status_code, 200)
        bob_tok = r_bob_reg.get_json()["api_token"]

        # Bob is isolated: cannot access admin endpoint, sees own status & config
        self.assertEqual(cli_bob.get("/api/admin/users").status_code, 403)
        st_bob = cli_bob.get("/api/status").get_json()
        self.assertEqual(st_bob["user"]["username"], "bob")
        self.assertEqual(st_bob["user"]["role"], "user")

        # Token routing works cleanly per user
        r_alice_tok_st = cli_anon.get("/api/status", headers={"X-API-Token": alice_tok})
        self.assertEqual(r_alice_tok_st.status_code, 200)
        self.assertEqual(r_alice_tok_st.get_json()["user"]["username"], "alice")

        # User-specific config change does not mutate admin config
        cli_bob.post("/api/config", json={"grab": {"xiao_campus": "嘉定"}})
        self.assertEqual(cli_admin.get("/api/config").get_json()["grab"]["xiao_campus"], "")
        self.assertEqual(cli_bob.get("/api/config").get_json()["grab"]["xiao_campus"], "嘉定")

        # Disabling bob revokes token & session immediately
        self.assertEqual(cli_admin.post("/api/admin/users", json={"action": "toggle", "username": "bob"}).status_code, 200)
        self.assertEqual(cli_anon.get("/api/status", headers={"X-API-Token": bob_tok}).status_code, 401)
        self.assertEqual(cli_bob.get("/api/status").status_code, 401)

    def test_cofire_throttle_admin_priority_and_per_user_proxy(self):
        cli_admin = self.app.test_client()
        self.assertEqual(cli_admin.post("/api/login", json={"username": "admin", "password": "adminpass123"}).status_code, 200)

        for uname, pw in (("stu1", "stupass1"), ("stu2", "stupass2")):
            r = cli_admin.post("/api/admin/users", json={"action": "create", "username": uname, "password": pw})
            if r.status_code != 200:
                self.assertIn("存在", str(r.get_json()))

        # Invalid proxy rejected; subuser forbidden from changing proxy
        self.assertEqual(
            cli_admin.post("/api/admin/users", json={"action": "set_proxy", "username": "stu1", "proxy_url": "ftp://1.2.3.4:21"}).status_code,
            400,
        )

        # Arm all 3 users on same lecture with shared direct exit ("")
        did = "LECTURE-COFIRE-1"
        rt_admin = srv.USER_RUNTIMES["admin"]
        rt_s1 = srv.USER_RUNTIMES["stu1"]
        rt_s2 = srv.USER_RUNTIMES["stu2"]
        for rt in (rt_admin, rt_s1, rt_s2):
            rt.set_proxy("")
            with rt.lock:
                rt.state["engine"]["locked"][did] = {"title": "Test", "lvl": "校级", "tgt": 1e12, "status": "grabbing", "auto": True}

        p_admin = srv._plan_grab_profile(rt_admin, did, 0.0)
        p_s1 = srv._plan_grab_profile(rt_s1, did, 0.0)
        p_s2 = srv._plan_grab_profile(rt_s2, did, 0.0)

        # Shared IP: admin keeps full burst & earlier lead; subusers are throttled and staggered
        self.assertEqual(p_admin["peers"], 3)
        self.assertEqual(p_admin["burst"], g.BURST)
        self.assertAlmostEqual(p_admin["volley_interval"], g.VOLLEY_INTERVAL, places=2)
        self.assertEqual(p_s1["burst"], 1)
        self.assertEqual(p_s2["burst"], 1)
        self.assertGreater(p_s1["volley_interval"], p_admin["volley_interval"])
        self.assertGreater(p_admin["lead"], p_s1["lead"])
        self.assertGreater(p_s1["lead"], p_s2["lead"])

        # Assign distinct mihomo exit proxies to stu1 & stu2 -> zero shared IP contention -> all 3 unthrottled!
        r_px1 = cli_admin.post("/api/admin/users", json={"action": "set_proxy", "username": "stu1", "proxy_url": "http://127.0.0.1:7891"})
        r_px2 = cli_admin.post("/api/admin/users", json={"action": "set_proxy", "username": "stu2", "proxy_url": "http://127.0.0.1:7892"})
        self.assertEqual(r_px1.status_code, 200)
        self.assertEqual(r_px2.status_code, 200)
        self.assertEqual(rt_s1.client._session.proxies.get("https"), "http://127.0.0.1:7891")
        self.assertEqual(rt_s2.client._session.proxies.get("https"), "http://127.0.0.1:7892")
        self.assertEqual(rt_admin.client._session.proxies, {})

        self.assertEqual(srv._plan_grab_profile(rt_admin, did, 0.0)["burst"], g.BURST)
        self.assertEqual(srv._plan_grab_profile(rt_s1, did, 0.0)["burst"], g.BURST)
        self.assertEqual(srv._plan_grab_profile(rt_s2, did, 0.0)["burst"], g.BURST)

        # Clean up synthetic lock entries
        for rt in (rt_admin, rt_s1, rt_s2):
            with rt.lock:
                rt.state["engine"]["locked"].pop(did, None)

    def test_dida365_time_parsing_and_idempotent_sync(self):
        s1, e1 = dida_mod.parse_lecture_time_range("2026-12-01 14:00~16:30")
        self.assertEqual(s1, "2026-12-01T14:00:00+0800")
        self.assertEqual(e1, "2026-12-01T16:30:00+0800")

        s2, e2 = dida_mod.parse_lecture_time_range("2026-12-01 19:00")
        self.assertEqual(s2, "2026-12-01T19:00:00+0800")
        self.assertEqual(e2, "2026-12-01T21:00:00+0800")

        cli_admin = self.app.test_client()
        self.assertEqual(cli_admin.post("/api/login", json={"username": "admin", "password": "adminpass123"}).status_code, 200)
        r_cfg = cli_admin.post("/api/config", json={"dida365": {"enabled": True, "token": "dp_test_token", "project_name": "🎓 同济讲座", "remind_before_min": 45}})
        self.assertEqual(r_cfg.status_code, 200)
        self.assertEqual(r_cfg.get_json()["cfg"]["dida365"]["remind_before_min"], 45)

        rt = srv.USER_RUNTIMES["admin"]
        with rt.lock:
            rt.state["engine"]["won"] = [
                {"did": "DIDA-UPCOMING-1", "title": "未来测试讲座", "lvl": "校级", "ltime": "2099-12-01 14:00~16:00", "won_at": "2026-11-25 18:00:00"},
                {"did": "DIDA-PAST-1", "title": "过期测试讲座", "lvl": "校级", "ltime": "2020-01-01 14:00~16:00", "won_at": "2020-01-01 10:00:00"},
            ]

        created_calls = []
        orig_ensure = dida_mod.ensure_project
        orig_create = dida_mod.create_lecture_task
        try:
            dida_mod.ensure_project = lambda tok, project_name="", project_id="": (True, "ok", "proj-123", project_name or "🎓 同济讲座")
            def _fake_create(tok, pid, lec, remind_before_min=60):
                created_calls.append((pid, lec["did"], remind_before_min))
                return True, "ok", "task-xyz-1"
            dida_mod.create_lecture_task = _fake_create

            r1 = cli_admin.post("/api/dida/sync").get_json()
            self.assertTrue(r1["ok"])
            self.assertEqual(r1["synced"], 1)
            self.assertEqual(r1["skipped"], 1)
            self.assertEqual(created_calls, [("proj-123", "DIDA-UPCOMING-1", 45)])

            # Second sync must be idempotent (0 new tasks)
            r2 = cli_admin.post("/api/dida/sync").get_json()
            self.assertEqual(r2["synced"], 0)
            self.assertEqual(r2["skipped"], 2)
        finally:
            dida_mod.ensure_project = orig_ensure
            dida_mod.create_lecture_task = orig_create
            with rt.lock:
                rt.state["engine"]["won"] = []


if __name__ == "__main__":
    unittest.main()

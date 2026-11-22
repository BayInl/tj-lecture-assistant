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


if __name__ == "__main__":
    unittest.main()

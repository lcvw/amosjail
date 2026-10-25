import os
import unittest

from amosjail import config
from amosjail.config import Bind, Caller, ConfigError

EXAMPLE = os.path.join(os.path.dirname(__file__), "..", "..", "etc", "amosjail.toml")
CALLER = Caller(uid=501, gid=20, user="liam", home="/Users/liam", cwd="/Users/liam/proj",
                env={"TERM": "xterm-256color", "SECRET": "x"})


def parse(text):
    return config.parse(text, "t.toml")


class ParseTest(unittest.TestCase):
    def test_example_loads(self):
        cfg = config.load(EXAMPLE)
        self.assertIn("agent", cfg.roles)
        self.assertEqual(cfg.amosproxy.socket, "/var/run/amosproxy.sock")
        self.assertEqual(cfg.mosbind.mount, "/sbin/mount")

    def test_defaults(self):
        cfg = parse("")
        self.assertEqual(cfg.daemon.jail_dir, "/var/amosjail")
        self.assertEqual(cfg.amosproxy.command, ("amosproxy",))

    def test_unknown_key_is_an_error(self):
        with self.assertRaisesRegex(ConfigError, r"t.toml.daemon: unknown key\(s\) jaildir"):
            parse('[daemon]\njaildir = "/x"')
        with self.assertRaisesRegex(ConfigError, "unknown key"):
            parse('[fragments.a]\nbinds = [{ source = "/a", target = "/a", mdoe = "rw" }]')

    def test_types_checked(self):
        with self.assertRaisesRegex(ConfigError, "socks_port: expected int"):
            parse('[amosproxy]\nsocks_port = "1"')
        with self.assertRaisesRegex(ConfigError, "invalid value 'tcp'"):
            parse('[roles.r]\nnetwork = "tcp"')

    def test_unknown_fragment(self):
        with self.assertRaisesRegex(ConfigError, "no fragment named 'nope'"):
            parse('[roles.r]\nfragments = ["nope"]')

    def test_overlay_needs_lower_and_workdir(self):
        with self.assertRaisesRegex(ConfigError, "needs lower"):
            parse('[fragments.a]\nbinds = [{ source = "/u", target = "/w", type = "overlay" }]')
        with self.assertRaisesRegex(ConfigError, "needs workdir"):
            parse('[fragments.a]\nbinds = [{ source = "/u", target = "/w", type = "overlay", mode = "rw", lower = ["/l"] }]')

    def test_relative_paths_rejected(self):
        with self.assertRaisesRegex(ConfigError, "must be an absolute path"):
            parse('[fragments.a]\nbinds = [{ source = "usr", target = "/usr" }]')

    def test_label_checked(self):
        with self.assertRaisesRegex(ConfigError, "label"):
            parse('[roles.r]\nproxy = { label = "a b" }')

    def test_amosproxy_argv(self):
        cfg = parse('[amosproxy]\ncommand = ["/opt/ap"]\nsocks_port = 1080')
        argv = cfg.amosproxy.daemon_argv("/var/db/amosjail/exempt.conf")
        self.assertEqual(argv[:4], ["/opt/ap", "--socket", "/var/run/amosproxy.sock", "daemon"])
        self.assertIn("1080", argv)
        self.assertEqual(argv[-2:], ["--exempt-file", "/var/db/amosjail/exempt.conf"])


class ResolveTest(unittest.TestCase):
    def setUp(self):
        self.cfg = config.load(EXAMPLE)

    def test_substitution_and_defaults(self):
        s = config.resolve(self.cfg, "agent", CALLER)
        work = [b for b in s.binds if b.target == "/work"][0]
        self.assertEqual(work.source, "/Users/liam/proj")
        self.assertEqual(s.cwd, "/work")
        self.assertEqual(s.env["TERM"], "xterm-256color")
        self.assertNotIn("SECRET", s.env)
        self.assertIn("/opt/homebrew/bin", s.env["PATH"])  # later fragment wins

    def test_param_override(self):
        s = config.resolve(self.cfg, "agent", CALLER, params={"PROJECT": "/tmp/p"})
        self.assertEqual([b for b in s.binds if b.target == "/work"][0].source, "/tmp/p")

    def test_param_not_allowed(self):
        with self.assertRaisesRegex(ConfigError, "does not take --param HOME"):
            config.resolve(self.cfg, "agent", CALLER, params={"HOME": "/"})

    def test_proxy_adds_ca_env_and_dns(self):
        s = config.resolve(self.cfg, "agent", CALLER)
        self.assertEqual(s.env["SSL_CERT_FILE"], "/Library/Application Support/amosproxy/ca-bundle.pem")
        self.assertIn(config.DNS_SOCKET, s.unix_sockets)
        # public_dir is visible through the /Library bind, so no extra bind
        self.assertFalse(any(b.target.startswith("/Library/") for b in s.binds))

    def test_proxy_binds_public_dir_when_not_visible(self):
        cfg = parse('[roles.r]\nnetwork = "proxy"\nbinds = [{ source = "/usr", target = "/usr" }]')
        s = config.resolve(cfg, "r", CALLER)
        self.assertIn("/Library/Application Support/amosproxy", [b.target for b in s.binds])

    def test_cli_binds(self):
        s = config.resolve(self.cfg, "agent", CALLER, cli_binds=[config.parse_cli_bind("data:/data")])
        self.assertIn(Bind(source="/Users/liam/proj/data", target="/data"), s.binds)
        with self.assertRaisesRegex(ConfigError, "only read-only"):
            config.resolve(self.cfg, "agent", CALLER, cli_binds=[config.parse_cli_bind("/a:/b:rw")])

    def test_allowed_users(self):
        cfg = parse('[roles.r]\nallowed_users = ["bob"]')
        with self.assertRaisesRegex(ConfigError, "not available to liam"):
            config.resolve(cfg, "r", CALLER)

    def test_undefined_var(self):
        cfg = parse('[roles.r]\nbinds = [{ source = "${NOPE}", target = "/x" }]')
        with self.assertRaisesRegex(ConfigError, r"\$\{NOPE\} is not defined"):
            config.resolve(cfg, "r", CALLER)

    def test_nested_bind_rejected(self):
        cfg = parse('[roles.r]\nbinds = [{ source = "/usr", target = "/usr" }, { source = "/opt", target = "/usr/local" }]')
        with self.assertRaisesRegex(ConfigError, "inside bind /usr"):
            config.resolve(cfg, "r", CALLER)

    def test_duplicate_target_rejected(self):
        cfg = parse('[roles.r]\nbinds = [{ source = "/a", target = "/x" }, { source = "/b", target = "/x/" }]')
        with self.assertRaisesRegex(ConfigError, "already used"):
            config.resolve(cfg, "r", CALLER)

    def test_dev_is_reserved(self):
        cfg = parse('[roles.r]\nbinds = [{ source = "/a", target = "/dev/x" }]')
        with self.assertRaisesRegex(ConfigError, "devfs"):
            config.resolve(cfg, "r", CALLER)

    def test_bind_under_link_rejected(self):
        cfg = parse('[roles.r]\nlinks = { "/etc" = "private/etc" }\nbinds = [{ source = "/etc", target = "/etc/x" }]')
        with self.assertRaisesRegex(ConfigError, "under link /etc"):
            config.resolve(cfg, "r", CALLER)


if __name__ == "__main__":
    unittest.main()

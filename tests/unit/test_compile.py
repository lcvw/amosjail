import os
import unittest

from amosjail import compile, config
from amosjail.config import Caller

EXAMPLE = os.path.join(os.path.dirname(__file__), "..", "..", "etc", "amosjail.toml")
GOLDEN = os.path.join(os.path.dirname(__file__), "golden")
CALLER = Caller(uid=501, gid=20, user="liam", home="/Users/liam", cwd="/Users/liam/proj")
ROOT = "/var/amosjail/501/j1/root"
R = "/private" + ROOT


def spec(toml, role="r"):
    return config.resolve(config.parse(toml, "t.toml"), role, CALLER)


class CompileTest(unittest.TestCase):
    def test_golden(self):
        """The example config's agent role. Regenerate with
        AMOSJAIL_REGOLD=1 after reviewing the diff."""
        s = config.resolve(config.load(EXAMPLE), "agent", CALLER)
        text = compile.render(s, ROOT, tty="ttys005")
        path = os.path.join(GOLDEN, "agent.sb")
        if os.environ.get("AMOSJAIL_REGOLD"):
            os.makedirs(GOLDEN, exist_ok=True)
            with open(path, "w") as f:
                f.write(text)
        with open(path) as f:
            self.assertEqual(text, f.read())

    def test_host_path(self):
        self.assertEqual(compile.host_path("/var/amosjail"), "/private/var/amosjail")
        self.assertEqual(compile.host_path("/tmp"), "/private/tmp")
        self.assertEqual(compile.host_path("/variable"), "/variable")
        self.assertEqual(compile.host_path("/private/var/x"), "/private/var/x")

    def test_paths_are_under_the_root(self):
        text = compile.render(spec('[roles.r]\nbinds = [{ source = "/usr", target = "/usr" }]'), ROOT)
        self.assertIn(f'(allow file-read* (subpath "{R}/usr"))', text)
        self.assertIn(f'(literal "{R}")', text)

    def test_mandatory_block_comes_last(self):
        s = spec('[roles.r]\nsbpl = "(allow process-info*)"\nsbpl_final = "; final"')
        text = compile.render(s, ROOT)
        self.assertLess(text.index("(allow process-info*)"), text.index("(deny process-info*)"))
        self.assertLess(text.index("(deny process-info*)"), text.index("; final"))
        self.assertIn("(deny file-ioctl (ioctl-command #x80017472))", text)
        self.assertTrue(text.startswith("(version 1)\n(deny default)\n"))

    def test_report_mode(self):
        text = compile.render(spec("[roles.r]"), ROOT, report=True)
        self.assertIn("(allow default (with report))", text)
        self.assertNotIn("(deny default)", text)
        self.assertIn("(deny process-info*)", text)  # the mandatory block stays

    def test_rw_defaults_and_anchor(self):
        s = spec('[roles.r]\nbinds = [{ source = "/p", target = "/work", mode = "rw", deny = [".env"] }]')
        text = compile.render(s, ROOT)
        self.assertIn(f'(subpath "{R}/work/.git/hooks")', text)
        # renaming .git away must be denied too
        anchors = [ln for ln in text.splitlines() if ln.startswith("(deny file-write* (literal")]
        self.assertIn(f'(literal "{R}/work/.git")', anchors[0])
        self.assertIn(f'(deny file-read* file-write* process-exec* (subpath "{R}/work/.env"))', text)
        self.assertIn(r"(regex #\"^", text.replace('#"', '#\\"'))  # **/.husky/**

    def test_ro_bind_has_no_default_denies(self):
        text = compile.render(spec('[roles.r]\nbinds = [{ source = "/p", target = "/work" }]'), ROOT)
        self.assertNotIn(".git/hooks", text)

    def test_deny_defaults_off(self):
        s = spec('[roles.r]\nbinds = [{ source = "/p", target = "/work", mode = "rw", deny_defaults = false }]')
        self.assertNotIn(".git", compile.render(s, ROOT))

    def test_glob_regex(self):
        self.assertEqual(compile.glob_to_regex("/a/**/.husky/**"), r"/a/(.*/)?\.husky/.*")
        self.assertEqual(compile.glob_to_regex("/a/*.sh"), r"/a/[^/]*\.sh")

    def test_network(self):
        none = compile.render(spec('[roles.r]\nnetwork = "none"'), ROOT)
        self.assertNotIn("network-outbound", none)
        prox = compile.render(spec('[roles.r]\nnetwork = "proxy"\nloopback = ["127.0.0.1:8080"]'), ROOT)
        self.assertLess(prox.index('(deny network-outbound (remote ip "localhost:*"))'),
                        prox.index('(allow network-outbound (remote tcp "localhost:8080"))'))
        self.assertNotIn("udp", prox)

    def test_dns_socket(self):
        text = compile.render(spec("[roles.r]\ndns = true"), ROOT)
        self.assertIn(f'(path-literal "/private/var/run/mDNSResponder") (path-literal "{R}/private/var/run/mDNSResponder")', text)
        self.assertIn(f'(literal "{R}/private/var/run")', text)

    def test_tty(self):
        text = compile.render(spec("[roles.r]"), ROOT, tty="ttys012")
        self.assertIn('(literal "/dev/ttys012")', text)
        self.assertIn(f'(literal "{R}/dev/tty")', text)
        with self.assertRaises(ValueError):
            compile.render(spec("[roles.r]"), ROOT, tty="../x")

    def test_proc_visibility_and_debug(self):
        text = compile.render(spec('[roles.r]\nproc_visibility = "names"\ndebug = true'), ROOT)
        self.assertGreater(text.index("process-info-listpids"), text.index("(deny process-info*)"))
        self.assertIn("(allow mach-priv-task-port (target same-sandbox))", text)

    def test_quoting(self):
        s = spec('[roles.r]\nbinds = [{ source = "/a", target = "/we\\"ird" }]')
        self.assertIn('we\\"ird', compile.render(s, ROOT))


if __name__ == "__main__":
    unittest.main()

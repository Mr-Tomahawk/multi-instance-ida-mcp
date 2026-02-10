"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import sys
import os
import json
import time
import socket
import idaapi
import idc
import ida_nalt
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


PORTS = [13337, 13338, 13339, 13340, 13341, 13342]
DISCOVERY_DIR = os.path.join(os.path.expanduser("~"), ".ida-mcp", "instances")


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


def _find_available_port():
    """Try each port in sequence, return first available."""
    for port in PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            sock.close()
            return port
        except OSError:
            continue
    return None


def _write_discovery_file(port):
    """Write instance info so the MCP server can discover us."""
    os.makedirs(DISCOVERY_DIR, exist_ok=True)
    # Clean stale files first
    _cleanup_stale_discovery_files()
    info = {
        "port": port,
        "pid": os.getpid(),
        "idb_path": idc.get_idb_path(),
        "binary_name": idaapi.get_root_filename(),
        "input_file_path": ida_nalt.get_input_file_path(),
        "start_time": time.time(),
    }
    # Optionally add arch/bits if easy to get
    try:
        info["bits"] = 64 if idaapi.get_inf_structure().is_64bit() else 32
    except Exception:
        pass
    path = os.path.join(DISCOVERY_DIR, f"{port}.json")
    with open(path, "w") as f:
        json.dump(info, f, indent=2)


def _remove_discovery_file(port):
    """Remove our discovery file on shutdown."""
    path = os.path.join(DISCOVERY_DIR, f"{port}.json")
    try:
        os.unlink(path)
    except OSError:
        pass


def _cleanup_stale_discovery_files():
    """Remove discovery files for processes that no longer exist."""
    if not os.path.isdir(DISCOVERY_DIR):
        return
    for fname in os.listdir(DISCOVERY_DIR):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(DISCOVERY_DIR, fname)
        try:
            with open(fpath) as f:
                info = json.load(f)
            pid = info.get("pid")
            if pid:
                os.kill(pid, 0)  # Check if process exists (signal 0 = no-op)
        except (ProcessLookupError, OSError, json.JSONDecodeError, KeyError):
            # Process is dead or file is corrupt — remove it
            try:
                os.unlink(fpath)
            except OSError:
                pass


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    # TODO: make these configurable
    HOST = "127.0.0.1"
    PORTS = [13337, 13338, 13339, 13340, 13341, 13342]

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
        )
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self.port: int | None = None
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        if self.mcp:
            self.mcp.stop()
            self.mcp = None

        # Find available port
        self.port = _find_available_port()
        if self.port is None:
            print("[MCP] Error: All ports (13337-13342) in use. Max 6 IDA instances supported.")
            return

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches, init_http

        try:
            init_http()
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        try:
            MCP_SERVER.serve(
                self.HOST, self.port, request_handler=IdaMcpHttpRequestHandler
            )
            _write_discovery_file(self.port)
            print(f"  Config: http://{self.HOST}:{self.port}/config.html")
            self.mcp = MCP_SERVER
        except OSError as e:
            if e.errno in (48, 98, 10048):  # Address already in use
                print(f"[MCP] Error: Port {self.port} is already in use")
            else:
                raise

    def term(self):
        if self.mcp:
            if self.port is not None:
                _remove_discovery_file(self.port)
            self.mcp.stop()


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX

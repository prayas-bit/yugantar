"""Multi-node enforcement for key rotation cutoffs and revocation propagation."""

from __future__ import annotations

from dataclasses import dataclass
import copy
import time
from typing import Dict, List, Optional, Tuple

from pqguard.keystore import KeyStore


@dataclass
class ServiceNode:
    node_id: str
    synced_epoch: int = 0
    last_sync_ts: float = 0.0
    key_versions: Dict[int, dict] = None  # type: ignore[assignment]
    revoked_versions: set[int] = None  # type: ignore[assignment]
    revoked_devices: set[str] = None  # type: ignore[assignment]
    devices: Dict[str, dict] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.key_versions is None:
            self.key_versions = {}
        if self.revoked_versions is None:
            self.revoked_versions = set()
        if self.revoked_devices is None:
            self.revoked_devices = set()
        if self.devices is None:
            self.devices = {}

    def sync_from(self, keystore: KeyStore) -> float:
        """Pull an isolated snapshot of key versions, devices, and revocations from keystore."""
        self.key_versions = {int(k): copy.deepcopy(v) for k, v in keystore.state["key_versions"].items()}
        self.revoked_versions = set(keystore.state.get("revoked_versions", []))
        self.devices = {dev_id: copy.deepcopy(dev) for dev_id, dev in keystore.state.get("devices", {}).items()}
        self.revoked_devices = {
            dev_id for dev_id, dev in self.devices.items() if dev.get("status") == "revoked"
        }
        self.synced_epoch = int(keystore.state.get("revocation_epoch", 0))
        self.last_sync_ts = time.perf_counter()
        return self.last_sync_ts

    def authorize_request(
        self,
        actor: str,
        device_id: str,
        key_version: int,
        keystore: Optional[KeyStore] = None,
        now: Optional[float] = None,
    ) -> Tuple[bool, str]:
        """Enforce device revocation and key-version rotation cutoff using only synced node state."""
        ts = time.time() if now is None else now
        if device_id in self.revoked_devices:
            return False, f"{self.node_id}:device_revoked"
        dev = self.devices.get(device_id)
        if dev is None or dev.get("actor") != actor or dev.get("status") != "active":
            return False, f"{self.node_id}:device_unauthorized"

        if key_version in self.revoked_versions:
            return False, f"{self.node_id}:key_version_revoked"
        rec = self.key_versions.get(key_version)
        if rec is None:
            return False, f"{self.node_id}:unknown_key_version"
        status = rec.get("status")
        if status == "active":
            return True, f"{self.node_id}:allow_active"
        if status == "grace":
            cutoff = rec.get("cutoff_at")
            if cutoff is not None and ts <= float(cutoff):
                return True, f"{self.node_id}:allow_grace"
            return False, f"{self.node_id}:past_rotation_cutoff"
        return False, f"{self.node_id}:key_version_{status}"


class NodeCluster:
    """Simulated multi-node service cluster for measuring propagation & enforcement."""

    def __init__(self, node_ids: List[str]) -> None:
        if not node_ids:
            raise ValueError("Cluster requires at least one node")
        self.nodes: Dict[str, ServiceNode] = {nid: ServiceNode(node_id=nid) for nid in node_ids}

    def sync_all(self, keystore: KeyStore) -> Dict[str, float]:
        """Synchronize all nodes and return per-node sync completion timestamps (perf_counter)."""
        return {nid: node.sync_from(keystore) for nid, node in self.nodes.items()}

    def propagate_revocation(self, keystore: KeyStore, revocation_start_perf: float) -> Dict[str, float]:
        """Push revocation to all nodes and report per-node & max propagation time in ms."""
        per_node_ms: Dict[str, float] = {}
        for nid, node in self.nodes.items():
            done = node.sync_from(keystore)
            per_node_ms[nid] = (done - revocation_start_perf) * 1000.0
        return {
            "max_propagation_ms": max(per_node_ms.values()),
            "per_node_ms": per_node_ms,
        }

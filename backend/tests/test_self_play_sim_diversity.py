"""P3/N 单元测试 — 仿真拓扑多样性 + 良性背景流量 + 分层新颖度。

兼容性红线:
- 默认 topology() 仍是 10 主机固定拓扑;
- 默认 SimEnv 首次外部攻击 src=203.0.113.50,foothold 后内部 src=10.0.30.11;
- NoveltyIndex 旧 score/observe/dump/load 语义不变。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

import asyncio

from self_play.catalog import get_ttp
from self_play.novelty import NoveltyIndex, layered_fingerprint, tokenize
from self_play.red_agent import RedAgent
from self_play.sim_env import ATTACKER_IP, HOSTS, SimEnv, generate_topology, topology
from self_play.types import MaterializedEvent


def _run(coro):
    return asyncio.run(coro)


class TestDefaultTopologyCompat:
    def test_topology_still_10_hosts_in_process_sim(self):
        topo = topology()
        assert len(topo["hosts"]) == 10
        assert topo["isolation"] == "in-process-sim"
        assert len(HOSTS) == 10
        assert ATTACKER_IP == "203.0.113.50"

    def test_default_materialize_external_then_foothold_src(self):
        env = SimEnv()
        red = RedAgent()
        s1 = red._step_from_spec(get_ttp("T1046"), set())
        s2 = red._step_from_spec(get_ttp("T1059"), set())
        evs = env.materialize_plan([s1, s2], [])
        assert evs[0].src_ip == "203.0.113.50"
        assert evs[1].src_ip == "10.0.30.11"
        assert evs[0].dst_ip == "10.0.10.10"


class TestGenerateTopology:
    def test_seed1_16_hosts_mixed_roles_zones(self):
        hosts = generate_topology(seed=1, n_hosts=16)
        assert len(hosts) == 16
        roles = {h["role"] for h in hosts}
        zones = {h["zone"] for h in hosts}
        assert len(roles) >= 3
        assert len(zones) >= 2
        assert roles <= {"web", "app", "db", "dc", "fs", "ws", "jump", "vpn", "mail", "dev"}
        assert zones <= {"dmz", "lan", "user", "isolated"}
        default_ips = {h["ip"] for h in HOSTS}
        assert {h["ip"] for h in hosts}.isdisjoint(default_ips)
        assert len({h["id"] for h in hosts}) == 16
        assert len({h["ip"] for h in hosts}) == 16

    def test_deterministic_and_seed_sensitive(self):
        a = generate_topology(seed=3, n_hosts=8)
        b = generate_topology(seed=3, n_hosts=8)
        c = generate_topology(seed=4, n_hosts=30)
        assert a == b
        assert a != c
        assert len(a) == 8 and len(c) == 30

    def test_bounds_clamped_8_to_30(self):
        assert len(generate_topology(seed=9, n_hosts=99)) == 30
        assert len(generate_topology(seed=9, n_hosts=2)) == 8
        assert 8 <= len(generate_topology(seed=9)) <= 30


class TestDiverseSimEnv:
    def test_diverse_internal_src_not_default_ws_ip(self):
        env = SimEnv(diverse=True, seed=2)
        assert len(env.hosts) >= 8
        red = RedAgent()
        s1 = red._step_from_spec(get_ttp("T1046"), set())
        s2 = red._step_from_spec(get_ttp("T1059"), set())
        evs = env.materialize_plan([s1, s2], [])
        assert evs[0].src_ip == "203.0.113.50"           # 外部起点不变
        internal_ips = {h["ip"] for h in env.hosts if h["role"] == "ws"}
        assert evs[1].src_ip in internal_ips
        assert evs[1].src_ip != "10.0.30.11"             # 不再恒等于默认跳板
        assert evs[0].dst_ip in {h["ip"] for h in env.hosts}
        assert evs[0].dst_ip != "10.0.10.10"

    def test_diverse_materialize_is_soc_log_not_exploit(self):
        env = SimEnv(diverse=True, seed=5)
        step = RedAgent()._step_from_spec(get_ttp("T1190"), set())
        log = env.materialize(step).to_log()
        blob = (log["message"] + log.get("url", "")).lower()
        assert log["_self_play"] is True
        assert log["_ground_truth"] == "attack"
        assert "or 1=1" not in blob
        assert "msfvenom" not in blob
        assert "sqlmap" not in blob


class TestBackgroundEvents:
    def test_all_benign_includes_dns_and_http(self):
        env = SimEnv(diverse=True, seed=11)
        evs = env.background_events(8)
        assert len(evs) == 8
        assert all(e.is_attack is False for e in evs)
        assert all(e.eval_channel == "sim" for e in evs)
        kinds = {e.event.upper() for e in evs}
        assert any("DNS" in k for k in kinds)
        assert any("HTTP" in k for k in kinds)
        # 不出网: 目标全部是拓扑内主机
        assert all(e.dst_ip in {h["ip"] for h in env.hosts} for e in evs)

    def test_default_env_background_uses_internal_hosts(self):
        env = SimEnv()
        evs = env.background_events(6)
        assert all(e.is_attack is False for e in evs)
        assert any("DNS" in e.event.upper() for e in evs)
        assert any("HTTP" in e.event.upper() for e in evs)
        assert all(e.dst_ip in {h["ip"] for h in HOSTS} for e in evs)

    def test_materialize_plan_appends_background(self):
        env = SimEnv()
        step = RedAgent()._step_from_spec(get_ttp("T1046"), set())
        evs = env.materialize_plan([step], [], background_n=4)
        assert len(evs) == 5
        assert sum(1 for e in evs if not e.is_attack) == 4


class TestLayeredNovelty:
    @staticmethod
    def _evt(**kw) -> MaterializedEvent:
        base = dict(
            event="PORT_SCAN", severity="medium", protocol="tcp",
            message="外部主机对内网进行端口扫描",
            src_ip="203.0.113.50", dst_ip="10.0.10.10",
            src_host="red-sim", dst_host="web-01",
            is_attack=True, ttp_id="ttp-t1046-scan", mitre_id="T1046",
            extra={"_kill_chain": "recon"},
        )
        base.update(kw)
        return MaterializedEvent(**base)

    def test_same_technique_diff_message_parameter_above_technique(self):
        idx = NoveltyIndex()
        idx.observe_event(self._evt())
        ln = idx.score_layered(self._evt(message="内网网段批量存活主机枚举"))
        assert ln.technique <= 0.05
        assert ln.parameter > ln.technique
        assert 0.0 <= ln.combined <= 1.0

    def test_layered_fingerprint_layers(self):
        fp = layered_fingerprint(self._evt(
            mitre_id="T1059.001", event="POSH_EXEC",
            message="PowerShell 解释器执行命令", extra={"_kill_chain": "execution"},
        ))
        assert fp["technique"] == ["T1059", "T1059.001"]
        assert "evt:POSH_EXEC" in fp["sequence"]
        assert "kc:execution" in fp["sequence"]
        assert "web-01" in fp["scenario"]
        # 技术层 token 不应混进参数层
        assert "T1059" not in fp["parameter"]

    def test_combined_weights(self):
        idx = NoveltyIndex()
        idx.observe_event(self._evt(mitre_id="T1059.001", event="POSH_EXEC",
                                    message="PowerShell 解释器执行命令",
                                    extra={"_kill_chain": "execution"},
                                    src_host="ws-01", dst_host="ws-02"))
        ln = idx.score_layered(self._evt(mitre_id="T1059.006", event="PY_INTERPRETER",
                                         message="Python 解释器执行脚本",
                                         extra={"_kill_chain": "execution"},
                                         src_host="ws-01", dst_host="ws-02"))
        # technique 层共享父技术 T1059 → jaccard 1/3 → 新颖 2/3
        assert abs(ln.technique - 2 / 3) < 1e-9
        assert ln.parameter == 1.0
        # sequence 层共享 kc:execution → jaccard 1/3 → 新颖 2/3
        assert abs(ln.sequence - 2 / 3) < 1e-9
        assert ln.scenario == 0.0
        expect = 0.4 * ln.technique + 0.3 * ln.parameter + 0.2 * ln.sequence + 0.1 * ln.scenario
        assert abs(ln.combined - expect) < 1e-9

    def test_old_score_unseen_one_then_zero(self):
        idx = NoveltyIndex()
        a = tokenize("PORT_SCAN", "外部主机对内网进行端口扫描")
        assert idx.score(a) == 1.0
        idx.observe(a)
        assert idx.score(a) == 0.0
        b = tokenize("SYN_ENUM", "大量半开连接探测服务存活状态")
        assert idx.score(b) > 0.3

    def test_dump_load_tokens_and_layered(self):
        idx = NoveltyIndex()
        idx.observe_event(self._evt())
        rows = idx.dump()
        idx2 = NoveltyIndex()
        idx2.load(rows)
        assert idx2.score(tokenize("PORT_SCAN", "外部主机对内网进行端口扫描", "T1046")) == 0.0
        idx2.load_layered(idx.dump_layered())
        ln = idx2.score_layered(self._evt())
        assert ln.technique == 0.0
        assert ln.sequence == 0.0

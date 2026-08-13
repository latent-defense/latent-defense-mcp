"""Unit tests for EnergyGraphCache (SQLite) and the tool modules."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile

import pytest

from latent_defense_mcp.energy_cache import EnergyGraphCache


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_fixture_cache(tmp_dir: str) -> EnergyGraphCache:
    """Build a cache with synthetic data in a temp SQLite database."""
    cache = EnergyGraphCache()
    cache.branch_id = "branch_test_123"
    cache.commit_id = "commit_abc"

    db_path = os.path.join(tmp_dir, "test.db")
    cache._db_path = db_path
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    cache._create_tables(conn)

    # 4 nodes
    nodes = [
        ("node-a", "service", json.dumps(["web frontend service"]), "{}", 1.5, "service"),
        ("node-b", "credential", json.dumps(["database credentials"]), "{}", 3.0, "credential"),
        ("node-c", "database", json.dumps(["production postgres"]), "{}", 5.0, "database"),
        ("node-d", "iam_role", json.dumps(["admin role"]), "{}", 0.8, "iam_role"),
    ]
    conn.executemany(
        "INSERT INTO nodes (name, type, semantic_context, metadata, entry_energy, energy_type) "
        "VALUES (?, ?, ?, ?, ?, ?)", nodes,
    )

    # 4 edges
    edges = [
        ("edge-a-b", "connects_to", "node-a", "node-b", json.dumps(["service uses credentials"]), "{}", -1.5, "connects_to"),
        ("edge-b-c", "authenticates", "node-b", "node-c", json.dumps(["creds authenticate to db"]), "{}", 2.0, "authenticates"),
        ("edge-a-d", "assumes", "node-a", "node-d", json.dumps(["service assumes iam role"]), "{}", -0.5, "assumes"),
        ("edge-d-c", "accesses", "node-d", "node-c", json.dumps(["role accesses database"]), "{}", -2.0, "accesses"),
    ]
    conn.executemany(
        "INSERT INTO edges (name, type, source, target, semantic_context, metadata, transition_energy, energy_type) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", edges,
    )
    conn.commit()
    conn.close()

    cache._n_nodes = 4
    cache._n_edges = 4
    cache._n_node_types = 4
    cache._n_edge_types = 4
    cache._n_containment = 0
    cache.loaded = True
    cache.has_energies = True
    return cache


@pytest.fixture
def cache(tmp_path):
    c = _build_fixture_cache(str(tmp_path))
    yield c
    c.close()


# ---------------------------------------------------------------------------
# EnergyGraphCache tests
# ---------------------------------------------------------------------------

class TestEnergyGraphCache:

    def test_basic_structure(self, cache: EnergyGraphCache):
        assert cache._n_nodes == 4
        assert cache._n_edges == 4
        assert cache.loaded is True
        assert cache.branch_id == "branch_test_123"

    def test_query_node(self, cache: EnergyGraphCache):
        node = cache.query_node("node-a")
        assert node is not None
        assert node["type"] == "service"
        assert node["entry_energy"] == 1.5

    def test_adjacency(self, cache: EnergyGraphCache):
        out = cache.get_outbound_edges("node-a")
        assert len(out) == 2  # edge-a-b, edge-a-d
        inb = cache.get_inbound_edges("node-c")
        assert len(inb) >= 1  # edge-b-c, edge-d-c

    def test_resolve_node(self, cache: EnergyGraphCache):
        assert cache.resolve_node("node-a") == "node-a"
        assert cache.resolve_node("postgres") == "node-c"  # semantic context match
        assert cache.resolve_node("nonexistent") is None

    def test_unloaded_cache(self):
        cache = EnergyGraphCache()
        assert cache.loaded is False
        assert cache.branch_id is None


# ---------------------------------------------------------------------------
# Graph tools tests
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.asyncio


class TestGraphTools:

    @pytest.fixture(autouse=True)
    def setup_tools(self, cache):
        from mcp.server.fastmcp import FastMCP
        from latent_defense_mcp import graph_tools

        self.mcp = FastMCP("test")
        self.cache = cache
        graph_tools.register(self.mcp, lambda: self.cache)

    async def test_read_node_found(self):
        fn = self.mcp._tool_manager._tools["read_node"].fn
        result = json.loads(await fn(name="node-a"))
        assert result["name"] == "node-a"
        assert result["type"] == "service"
        assert result["outbound_edges"] == 2

    async def test_read_node_substring(self):
        fn = self.mcp._tool_manager._tools["read_node"].fn
        result = json.loads(await fn(name="postgres"))
        assert result["name"] == "node-c"

    async def test_read_node_not_found(self):
        fn = self.mcp._tool_manager._tools["read_node"].fn
        result = json.loads(await fn(name="nonexistent"))
        assert "error" in result

    async def test_read_edge(self):
        fn = self.mcp._tool_manager._tools["read_edge"].fn
        result = json.loads(await fn(name="edge-a-b"))
        assert result["source"] == "node-a"
        assert result["target"] == "node-b"

    async def test_get_connected_edges(self):
        fn = self.mcp._tool_manager._tools["get_connected_edges"].fn
        result = json.loads(await fn(node_name="node-a", direction="outbound"))
        assert result["count"] == 2

    async def test_get_graph_statistics(self):
        fn = self.mcp._tool_manager._tools["get_graph_statistics"].fn
        result = json.loads(await fn())
        assert result["n_nodes"] == 4
        assert result["n_edges"] == 4

    async def test_grep_nodes(self):
        fn = self.mcp._tool_manager._tools["grep_nodes"].fn
        result = json.loads(await fn(pattern="node-a"))
        assert result["count"] == 1

    async def test_grep_nodes_context(self):
        fn = self.mcp._tool_manager._tools["grep_nodes"].fn
        result = json.loads(await fn(pattern="postgres", field="context"))
        assert result["count"] == 1
        assert result["nodes"][0]["name"] == "node-c"

    async def test_grep_edges(self):
        fn = self.mcp._tool_manager._tools["grep_edges"].fn
        result = json.loads(await fn(pattern="edge-a"))
        assert result["count"] == 2

    async def test_find_nodes_by_type(self):
        fn = self.mcp._tool_manager._tools["find_nodes_by_type"].fn
        result = json.loads(await fn(node_type="service"))
        assert result["count"] == 1

    async def test_find_edges_by_type(self):
        fn = self.mcp._tool_manager._tools["find_edges_by_type"].fn
        result = json.loads(await fn(edge_type="connects_to"))
        assert result["count"] == 1

    async def test_gate_no_cache(self):
        from mcp.server.fastmcp import FastMCP
        from latent_defense_mcp import graph_tools as gt
        mcp2 = FastMCP("test2")
        gt.register(mcp2, lambda: None)
        fn = mcp2._tool_manager._tools["read_node"].fn
        result = json.loads(await fn(name="node-a"))
        assert "error" in result


# ---------------------------------------------------------------------------
# Energy tools tests
# ---------------------------------------------------------------------------


class TestEnergyTools:

    @pytest.fixture(autouse=True)
    def setup_tools(self, cache):
        from mcp.server.fastmcp import FastMCP
        from latent_defense_mcp import energy_tools

        self.mcp = FastMCP("test")
        self.cache = cache
        energy_tools.register(self.mcp, lambda: self.cache)

    async def test_energy_node_scores(self):
        fn = self.mcp._tool_manager._tools["energy_node_scores"].fn
        result = json.loads(await fn(node_query="node-a"))
        assert result["matches"] == 1
        node = result["nodes"][0]
        assert node["node_id"] == "node-a"
        assert node["entry_energy"] == 1.5
        assert node["total_outbound"] == 2

    async def test_energy_node_scores_context_search(self):
        fn = self.mcp._tool_manager._tools["energy_node_scores"].fn
        result = json.loads(await fn(node_query="postgres"))
        assert result["matches"] == 1

    async def test_energy_edge_scores(self):
        fn = self.mcp._tool_manager._tools["energy_edge_scores"].fn
        result = json.loads(await fn(source_query="node-a"))
        assert len(result["edges"]) == 2

    async def test_energy_momentum_path(self):
        fn = self.mcp._tool_manager._tools["energy_momentum_path"].fn
        result = json.loads(await fn(node_names="node-a,node-d,node-c"))
        assert "error" not in result
        assert result["path_length"] == 3
        assert result["steps"][1]["accelerating"] is True

    async def test_energy_momentum_path_json(self):
        fn = self.mcp._tool_manager._tools["energy_momentum_path"].fn
        result = json.loads(await fn(node_names='["node-a", "node-b", "node-c"]'))
        assert result["path_length"] == 3

    async def test_energy_lowest_hop(self):
        fn = self.mcp._tool_manager._tools["energy_lowest_hop"].fn
        result = json.loads(await fn(node_query="node-a"))
        assert result["total_hops"] == 2
        assert result["lowest_energy_hop"]["transition_energy"] == -1.5

    async def test_energy_entry_points(self):
        fn = self.mcp._tool_manager._tools["energy_entry_points"].fn
        result = json.loads(await fn(threshold=2.0))
        assert result["count"] == 2  # node-d (0.8) and node-a (1.5)

    async def test_energy_defenses(self):
        fn = self.mcp._tool_manager._tools["energy_defenses"].fn
        result = json.loads(await fn())
        assert result["count"] >= 1

    async def test_energy_top_attack_paths(self):
        fn = self.mcp._tool_manager._tools["energy_top_attack_paths"].fn
        result = json.loads(await fn())
        assert "total_enumerated" in result

    async def test_energy_chokepoints(self):
        fn = self.mcp._tool_manager._tools["energy_chokepoints"].fn
        result = json.loads(await fn())
        assert "total_paths" in result

    async def test_energy_node_neighborhood(self):
        fn = self.mcp._tool_manager._tools["energy_node_neighborhood"].fn
        result = json.loads(await fn(node_query="node-a", hops=1))
        assert result["nodes"] >= 2

    async def test_energy_lowest_paths(self):
        fn = self.mcp._tool_manager._tools["energy_lowest_paths"].fn
        result = json.loads(await fn(node_query="node-a", max_hops=3))
        assert "by_depth" in result

    async def test_energy_trace_to_target(self):
        fn = self.mcp._tool_manager._tools["energy_trace_to_target"].fn
        result = json.loads(await fn(source_query="node-a", target_query="node-c"))
        assert result["reachable"] is True

    async def test_energy_compare_paths(self):
        fn = self.mcp._tool_manager._tools["energy_compare_paths"].fn
        result = json.loads(await fn(path_a="node-a,node-b,node-c", path_b="node-a,node-d,node-c"))
        assert "comparison" in result

    async def test_gate_no_cache(self):
        from mcp.server.fastmcp import FastMCP
        from latent_defense_mcp import energy_tools as et
        mcp2 = FastMCP("test2")
        et.register(mcp2, lambda: None)
        fn = mcp2._tool_manager._tools["energy_node_scores"].fn
        result = json.loads(await fn(node_query="anything"))
        assert "error" in result


# ---------------------------------------------------------------------------
# Triage state tools tests
# ---------------------------------------------------------------------------


class TestTriageStateTools:

    @pytest.fixture(autouse=True)
    def setup_tools(self, tmp_path):
        from mcp.server.fastmcp import FastMCP
        from latent_defense_mcp import triage_state

        self.mcp = FastMCP("test")
        os.environ["TRIAGE_STATE_DIR"] = str(tmp_path)
        triage_state.register(self.mcp)
        self._tmp = tmp_path
        yield
        os.environ.pop("TRIAGE_STATE_DIR", None)

    async def test_save_and_load_user(self):
        save_fn = self.mcp._tool_manager._tools["triage_save_user"].fn
        load_fn = self.mcp._tool_manager._tools["triage_load_user"].fn

        result = json.loads(await save_fn(user=json.dumps({"name": "Alice", "role": "engineer"})))
        assert result["user_id"] == "alice"

        loaded = json.loads(await load_fn(name="Alice"))
        assert loaded["name"] == "Alice"

    async def test_load_user_not_found(self):
        load_fn = self.mcp._tool_manager._tools["triage_load_user"].fn
        result = json.loads(await load_fn(name="nobody"))
        assert "error" in result

    async def test_save_and_load_project(self):
        save_fn = self.mcp._tool_manager._tools["triage_save_project"].fn
        load_fn = self.mcp._tool_manager._tools["triage_load_project"].fn

        result = json.loads(await save_fn(
            project_id="proj-1",
            project=json.dumps({"branch_id": "branch_test_123", "sources": [{"name": "test"}]}),
        ))
        assert result["project_id"] == "proj-1"

        loaded = json.loads(await load_fn(project_id="proj-1"))
        assert loaded["branch_id"] == "branch_test_123"

    async def test_list_projects(self):
        save_fn = self.mcp._tool_manager._tools["triage_save_project"].fn
        list_fn = self.mcp._tool_manager._tools["triage_list_projects"].fn

        await save_fn(project_id="p1", project=json.dumps({"branch_id": "branch_a"}))
        await save_fn(project_id="p2", project=json.dumps({"branch_id": "branch_b"}))

        result = json.loads(await list_fn())
        assert len(result["projects"]) == 2

    async def test_update_finding_group(self):
        save_fn = self.mcp._tool_manager._tools["triage_save_project"].fn
        update_fn = self.mcp._tool_manager._tools["triage_update_finding_group"].fn

        await save_fn(project_id="p1", project=json.dumps({
            "finding_groups": [{"id": "FG-1", "status": "pending"}],
        }))
        result = json.loads(await update_fn(
            project_id="p1", group_id="FG-1", update=json.dumps({"status": "fixed"}),
        ))
        assert result["updated"]["status"] == "fixed"

    async def test_add_work_item(self):
        save_fn = self.mcp._tool_manager._tools["triage_save_project"].fn
        add_fn = self.mcp._tool_manager._tools["triage_add_work_item"].fn

        await save_fn(project_id="p1", project=json.dumps({}))
        result = json.loads(await add_fn(
            project_id="p1", work_item=json.dumps({"title": "Fix the bug", "assignee": "Bob"}),
        ))
        assert result["work_item"]["id"] == "WI-1"

    async def test_add_decision(self):
        save_fn = self.mcp._tool_manager._tools["triage_save_project"].fn
        dec_fn = self.mcp._tool_manager._tools["triage_add_decision"].fn

        await save_fn(project_id="p1", project=json.dumps({}))
        result = json.loads(await dec_fn(
            project_id="p1", decision=json.dumps({"decision": "accept_risk", "justification": "low impact"}),
        ))
        assert result["decision"]["id"] == "DEC-1"

    async def test_project_status(self):
        save_fn = self.mcp._tool_manager._tools["triage_save_project"].fn
        status_fn = self.mcp._tool_manager._tools["triage_project_status"].fn

        await save_fn(project_id="p1", project=json.dumps({
            "branch_id": "branch_test_123",
            "finding_groups": [{"id": "FG-1", "status": "pending"}, {"id": "FG-2", "status": "fixed"}],
            "work_items": [{"id": "WI-1", "status": "open", "title": "Test"}],
        }))
        result = json.loads(await status_fn(project_id="p1"))
        assert result["finding_groups"]["total"] == 2
        assert result["work_items"]["total"] == 1

    async def test_get_workflow_args_ready(self):
        save_fn = self.mcp._tool_manager._tools["triage_save_project"].fn
        args_fn = self.mcp._tool_manager._tools["triage_get_workflow_args"].fn

        findings = self._tmp / "findings.json"
        findings.write_text("[]")

        await save_fn(project_id="p1", project=json.dumps({
            "branch_id": "branch_test_123",
            "sources": [{"path": str(findings), "name": "test-scanner"}],
            "audiences": [{"name": "Engineering"}],
            "deployment_model": "single-tenant",
            "verification_channels": [
                {"type": "source_code", "method": "github_api", "access": {"org": "my-org"},
                 "scope": "all repos", "instructions": "Use gh api"},
            ],
        }))
        result = json.loads(await args_fn(project_id="p1"))
        assert result["status"] == "ready"
        assert result["args"]["branch_id"] == "branch_test_123"
        assert len(result["args"]["verification_channels"]) == 1
        if result["gaps"]:
            assert not any(g["field"] == "deployment_model" for g in result["gaps"])
            assert not any(g["field"] == "verification_channels" for g in result["gaps"])

    async def test_get_workflow_args_missing_branch(self):
        save_fn = self.mcp._tool_manager._tools["triage_save_project"].fn
        args_fn = self.mcp._tool_manager._tools["triage_get_workflow_args"].fn

        await save_fn(project_id="p1", project=json.dumps({
            "sources": [{"name": "test"}], "audiences": [{"name": "Eng"}],
        }))
        result = json.loads(await args_fn(project_id="p1"))
        assert "error" in result
        assert any("branch_id" in e for e in result["errors"])

    async def test_get_workflow_args_gaps(self):
        save_fn = self.mcp._tool_manager._tools["triage_save_project"].fn
        args_fn = self.mcp._tool_manager._tools["triage_get_workflow_args"].fn

        findings = self._tmp / "findings.json"
        findings.write_text("[]")

        await save_fn(project_id="p1", project=json.dumps({
            "branch_id": "branch_test_123",
            "sources": [{"path": str(findings), "name": "scanner"}],
            "audiences": [{"name": "Eng"}],
        }))
        result = json.loads(await args_fn(project_id="p1"))
        assert result["status"] == "ready"
        assert any(g["field"] == "deployment_model" for g in result["gaps"])
        assert any(g["field"] == "verification_channels" for g in result["gaps"])

    async def test_get_workflow_args_legacy_source_code_not_migrated(self):
        """Legacy source_code field is NOT auto-migrated — we don't know the access method."""
        save_fn = self.mcp._tool_manager._tools["triage_save_project"].fn
        args_fn = self.mcp._tool_manager._tools["triage_get_workflow_args"].fn

        findings = self._tmp / "findings.json"
        findings.write_text("[]")

        await save_fn(project_id="p1", project=json.dumps({
            "branch_id": "branch_test_123",
            "sources": [{"path": str(findings), "name": "scanner"}],
            "audiences": [{"name": "Eng"}],
            "source_code": ["/path/to/repo1", "/path/to/repo2"],
        }))
        result = json.loads(await args_fn(project_id="p1"))
        # Legacy source_code is ignored — verification_channels is empty
        assert result["args"]["verification_channels"] == []
        # Shows up as a gap prompting the user to configure channels
        assert any(g["field"] == "verification_channels" for g in result["gaps"])

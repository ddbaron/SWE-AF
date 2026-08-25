"""Coverage and propagation tests for SWE-AF's harness profile registry."""

from __future__ import annotations

import ast
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("AGENTFIELD_SERVER", "http://localhost:9999")

from agentfield.types import ProfileId

from swe_af.runtime.profiles import (
    ALIASES,
    CANONICAL_PROFILE_ENTRIES,
    DIRECT_PROFILE_KEYS,
    PROFILE_REGISTRY,
    ProfileLookupError,
    profile_for,
)

ROOT = Path(__file__).resolve().parents[1]


EXPECTED_DIRECT_SITES: dict[tuple[str, str], str] = {
    ("swe_af/reasoners/pipeline.py", "run_product_manager"): "swe_af.main.pm",
    ("swe_af/reasoners/pipeline.py", "run_environment_scout"): "swe_af.main.environment_scout",
    ("swe_af/reasoners/pipeline.py", "run_architect"): "swe_af.main.architect",
    ("swe_af/reasoners/pipeline.py", "run_tech_lead"): "swe_af.main.tech_lead",
    ("swe_af/reasoners/pipeline.py", "run_sprint_planner"): "swe_af.main.sprint_planner",
    ("swe_af/reasoners/execution_agents.py", "run_retry_advisor"): "swe_af.main.retry_advisor",
    ("swe_af/reasoners/execution_agents.py", "run_issue_advisor"): "swe_af.main.issue_advisor",
    ("swe_af/reasoners/execution_agents.py", "run_replanner"): "swe_af.main.replanner",
    ("swe_af/reasoners/execution_agents.py", "run_issue_writer"): "swe_af.main.issue_writer",
    ("swe_af/reasoners/execution_agents.py", "run_verifier"): "swe_af.main.verifier",
    ("swe_af/reasoners/execution_agents.py", "run_git_init"): "swe_af.main.git_init",
    ("swe_af/reasoners/execution_agents.py", "run_workspace_setup"): "swe_af.main.workspace_setup",
    ("swe_af/reasoners/execution_agents.py", "run_merger"): "swe_af.main.merger",
    ("swe_af/reasoners/execution_agents.py", "run_integration_tester"): "swe_af.main.integration_tester",
    ("swe_af/reasoners/execution_agents.py", "run_workspace_cleanup"): "swe_af.main.workspace_cleanup",
    ("swe_af/reasoners/execution_agents.py", "run_coder"): "swe_af.main.coder",
    ("swe_af/reasoners/execution_agents.py", "run_qa"): "swe_af.main.qa",
    ("swe_af/reasoners/execution_agents.py", "run_code_reviewer"): "swe_af.main.code_reviewer",
    ("swe_af/reasoners/execution_agents.py", "generate_fix_issues"): "swe_af.main.fix_issues",
    ("swe_af/reasoners/execution_agents.py", "run_repo_finalize"): "swe_af.main.repo_finalize",
    ("swe_af/reasoners/execution_agents.py", "run_github_pr"): "swe_af.main.github_pr",
    ("swe_af/reasoners/execution_agents.py", "run_ci_fixer"): "swe_af.main.ci_fixer",
    ("swe_af/reasoners/execution_agents.py", "run_pr_resolver"): "swe_af.main.pr_resolver",
    ("swe_af/fast/planner.py", "fast_plan_tasks"): "swe_af.fast.plan_tasks",
    ("swe_af/execution/_replanner_compat.py", "invoke_replanner"): "swe_af.compat.replanner",
}

EXPECTED_ALIASES = {
    "swe_af.fast.run_git_init": "swe_af.main.git_init",
    "swe_af.fast.run_coder": "swe_af.main.coder",
    "swe_af.fast.run_verifier": "swe_af.main.verifier",
    "swe_af.fast.run_repo_finalize": "swe_af.main.repo_finalize",
    "swe_af.fast.run_github_pr": "swe_af.main.github_pr",
    "swe_af.fast.run_ci_watcher": "swe_af.main.ci_watcher",
    "swe_af.fast.run_ci_fixer": "swe_af.main.ci_fixer",
    "swe_af.fast.execute_tasks": "swe_af.main.coder",
    "swe_af.fast.verify": "swe_af.main.verifier",
    "swe_af.compat.replanner": "swe_af.main.replanner",
}


class _HarnessSiteVisitor(ast.NodeVisitor):
    """Collect direct router harness calls and their explicit profile lookup."""

    def __init__(self) -> None:
        self.function_stack: list[str] = []
        self.sites: list[tuple[str, str | None, int, int]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        if not self._is_router_harness_call(node):
            self.generic_visit(node)
            return

        profile_keywords = [keyword for keyword in node.keywords if keyword.arg == "profile"]
        profile_key: str | None = None
        if len(profile_keywords) == 1:
            value = profile_keywords[0].value
            if (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "profile_for"
                and value.args
                and isinstance(value.args[0], ast.Constant)
                and isinstance(value.args[0].value, str)
            ):
                profile_key = value.args[0].value

        owner = self.function_stack[0] if self.function_stack else ""
        self.sites.append((owner, profile_key, node.lineno, len(profile_keywords)))
        self.generic_visit(node)

    @staticmethod
    def _is_router_harness_call(node: ast.Call) -> bool:
        function = node.func
        return (
            isinstance(function, ast.Attribute)
            and function.attr == "harness"
            and isinstance(function.value, ast.Name)
            and function.value.id in {"router", "fast_router"}
        )


def _direct_harness_sites() -> list[tuple[str, str, str | None, int, int]]:
    paths = (
        "swe_af/reasoners/pipeline.py",
        "swe_af/reasoners/execution_agents.py",
        "swe_af/fast/planner.py",
        "swe_af/execution/_replanner_compat.py",
    )
    sites: list[tuple[str, str, str | None, int, int]] = []
    for relative_path in paths:
        visitor = _HarnessSiteVisitor()
        visitor.visit(ast.parse((ROOT / relative_path).read_text()))
        sites.extend(
            (relative_path, owner, profile_key, line, profile_count)
            for owner, profile_key, line, profile_count in visitor.sites
        )
    return sites


def test_every_direct_harness_site_has_one_registry_profile_lookup() -> None:
    sites = _direct_harness_sites()
    observed = {(path, owner): profile_key for path, owner, profile_key, _, _ in sites}

    assert len(sites) == len(observed) == len(EXPECTED_DIRECT_SITES)
    assert observed == EXPECTED_DIRECT_SITES
    assert set(DIRECT_PROFILE_KEYS) == set(EXPECTED_DIRECT_SITES.values())

    for path, owner, profile_key, line, profile_count in sites:
        assert profile_count == 1, f"{path}:{line} must pass exactly one profile lookup"
        assert profile_key is not None, f"{path}:{line} is missing profile_for(...)"
        entry = PROFILE_REGISTRY[profile_key]
        assert entry.direct_harness
        assert entry.source_file == path
        assert entry.source_symbol == owner
        assert entry.source_call_index == 1
        assert profile_for(profile_key, "open_code") == entry.profile_id


def test_registry_ids_are_unique_and_aliases_share_target_identity() -> None:
    canonical_ids = [str(entry.profile_id) for entry in CANONICAL_PROFILE_ENTRIES]
    assert all(canonical_ids)
    assert len(canonical_ids) == len(set(canonical_ids))

    assert set(ALIASES) == set(EXPECTED_ALIASES)
    for alias_key, target_key in EXPECTED_ALIASES.items():
        alias = PROFILE_REGISTRY[alias_key]
        target = PROFILE_REGISTRY[target_key]
        assert alias.delegate_of == target_key
        assert alias.profile_id == target.profile_id
        assert alias.policy_id == target.policy_id
        assert alias.source_call_index == (1 if alias.direct_harness else None)

    assert PROFILE_REGISTRY["swe_af.compat.replanner"].direct_harness
    assert not PROFILE_REGISTRY["swe_af.fast.run_ci_watcher"].direct_harness
    assert PROFILE_REGISTRY["swe_af.fast.plan_tasks"].delegate_of is None
    assert PROFILE_REGISTRY["swe_af.fast.plan_tasks"].profile_id not in {
        PROFILE_REGISTRY["swe_af.main.coder"].profile_id,
        PROFILE_REGISTRY["swe_af.main.verifier"].profile_id,
    }


def test_non_harness_roles_are_registered_without_profiles() -> None:
    for key in ("swe_af.main.qa_synthesizer", "swe_af.main.ci_watcher"):
        entry = PROFILE_REGISTRY[key]
        assert not entry.direct_harness
        assert entry.profile_id is None
        assert profile_for(key, "open_code") is None


@pytest.mark.parametrize("runtime", ["claude", "claude_code", "claude-code", "codex"])
def test_non_open_code_runtimes_remain_profileless(runtime: str) -> None:
    assert profile_for("swe_af.main.coder", runtime) is None


def test_open_code_aliases_resolve_to_their_canonical_profile() -> None:
    assert profile_for("swe_af.fast.run_coder", "opencode") == ProfileId(
        "swe_af.main.coder"
    )
    assert profile_for("swe_af.fast.execute_tasks", "open_code") == ProfileId(
        "swe_af.main.coder"
    )
    assert profile_for("swe_af.fast.verify", "open_code") == ProfileId(
        "swe_af.main.verifier"
    )
    assert profile_for("swe_af.compat.replanner", "open_code") == ProfileId(
        "swe_af.main.replanner"
    )


def test_unknown_profile_path_fails_closed() -> None:
    with pytest.raises(ProfileLookupError):
        profile_for("swe_af.main.new_role", "open_code")


def _response(parsed: object) -> SimpleNamespace:
    return SimpleNamespace(parsed=parsed, is_error=False, error_message="")


@pytest.mark.asyncio
async def test_product_manager_passes_profile_without_changing_hax_flow(tmp_path: Path) -> None:
    from swe_af.reasoners import pipeline
    from swe_af.reasoners.schemas import PRD

    mock_router = MagicMock()
    mock_router.harness = AsyncMock(
        return_value=_response(
            PRD(
                validated_description="Build it",
                acceptance_criteria=["It works"],
                must_have=["The feature"],
                nice_to_have=[],
                out_of_scope=[],
            )
        )
    )

    with (
        patch.object(pipeline, "router", mock_router),
        patch("swe_af.hitl.build_hax_client_from_env", return_value=None),
        patch("swe_af.hitl.approval_webhook_url", return_value=None),
    ):
        result = await pipeline.run_product_manager(
            goal="Build it",
            repo_path=str(tmp_path),
            ai_provider="open_code",
            model="openrouter/test-model",
        )

    assert result["validated_description"] == "Build it"
    kwargs = mock_router.harness.await_args.kwargs
    assert kwargs["provider"] == "opencode"
    assert kwargs["profile"] == ProfileId("swe_af.main.pm")
    assert kwargs["model"] == "openrouter/test-model"
    assert kwargs["cwd"] == str(tmp_path)


@pytest.mark.asyncio
async def test_coder_passes_profile_and_preserves_harness_arguments(tmp_path: Path) -> None:
    from swe_af.execution.schemas import CoderResult
    from swe_af.reasoners import execution_agents

    mock_router = MagicMock()
    mock_router.harness = AsyncMock(
        return_value=_response(CoderResult(summary="implemented", complete=True))
    )

    with patch.object(execution_agents, "router", mock_router):
        result = await execution_agents.run_coder(
            issue={"name": "add-feature"},
            worktree_path=str(tmp_path),
            model="openrouter/test-model",
            ai_provider="open_code",
        )

    assert result["summary"] == "implemented"
    kwargs = mock_router.harness.await_args.kwargs
    assert kwargs["provider"] == "opencode"
    assert kwargs["profile"] == ProfileId("swe_af.main.coder")
    assert kwargs["model"] == "openrouter/test-model"
    assert kwargs["cwd"] == str(tmp_path)
    assert kwargs["tools"] == ["Read", "Write", "Edit", "Bash", "Glob", "Grep"]


@pytest.mark.asyncio
async def test_code_reviewer_passes_profile(tmp_path: Path) -> None:
    from swe_af.execution.schemas import CodeReviewResult
    from swe_af.reasoners import execution_agents

    mock_router = MagicMock()
    mock_router.harness = AsyncMock(
        return_value=_response(CodeReviewResult(approved=True, summary="approved"))
    )

    with patch.object(execution_agents, "router", mock_router):
        result = await execution_agents.run_code_reviewer(
            worktree_path=str(tmp_path),
            coder_result={},
            issue={"name": "add-feature", "title": "Add feature"},
            ai_provider="opencode",
        )

    assert result["approved"] is True
    kwargs = mock_router.harness.await_args.kwargs
    assert kwargs["profile"] == ProfileId("swe_af.main.code_reviewer")
    assert kwargs["provider"] == "opencode"


@pytest.mark.asyncio
async def test_fast_planner_passes_distinct_profile(tmp_path: Path) -> None:
    from swe_af.fast import planner
    from swe_af.fast.schemas import FastPlanResult

    mock_router = MagicMock()
    mock_router.harness = AsyncMock(
        return_value=_response(FastPlanResult(tasks=[]))
    )

    with patch.object(planner, "fast_router", mock_router), patch.object(
        planner, "_note"
    ):
        result = await planner.fast_plan_tasks(
            goal="Build it",
            repo_path=str(tmp_path),
            ai_provider="open_code",
        )

    assert result["tasks"] == []
    kwargs = mock_router.harness.await_args.kwargs
    assert kwargs["profile"] == ProfileId("swe_af.fast.plan_tasks")
    assert kwargs["provider"] == "opencode"


@pytest.mark.asyncio
async def test_compat_replanner_passes_shared_profile(tmp_path: Path) -> None:
    from swe_af.execution import _replanner_compat
    from swe_af.execution.schemas import (
        DAGState,
        ExecutionConfig,
        ReplanAction,
        ReplanDecision,
    )

    mock_router = MagicMock()
    mock_router.harness = AsyncMock(
        return_value=_response(
            ReplanDecision(action=ReplanAction.CONTINUE, rationale="continue")
        )
    )

    with patch.object(_replanner_compat, "router", mock_router):
        result = await _replanner_compat.invoke_replanner(
            DAGState(repo_path=str(tmp_path)),
            [],
            ExecutionConfig(runtime="open_code"),
        )

    assert result.action is ReplanAction.CONTINUE
    kwargs = mock_router.harness.await_args.kwargs
    assert kwargs["profile"] == ProfileId("swe_af.main.replanner")
    assert kwargs["provider"] == "opencode"


@pytest.mark.asyncio
async def test_external_profile_source_reaches_opencode_from_sweaf_role(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise a real SWE-AF role through AgentField and a file-backed profile."""
    from agentfield import HarnessConfig

    import swe_af.app as app_module
    from swe_af.prompts.product_manager import SYSTEM_PROMPT
    from swe_af.reasoners import pipeline

    profile_path = tmp_path / "opencode-profiles.json"
    profile_path.write_text(
        json.dumps(
            {
                "contract_version": "v1",
                "provider": "opencode",
                "minimum_version": "1.18.0",
                "profiles": {
                    "swe_af.main.pm": {
                        "mode": "primary",
                        "model": "openrouter/external-profile#profile-default",
                        "prompt": "External AgentField PM profile instructions.",
                        "permission": {
                            "read": "allow",
                            "edit": "allow",
                            "bash": "allow",
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    fake_opencode = tmp_path / "fake-opencode"
    fake_opencode.write_text(
        "#!" + sys.executable + "\n"
        + r'''
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _record(record: dict[str, object]) -> None:
    log_path = os.environ.get("FAKE_OPENCODE_LOG")
    if not log_path:
        return
    with Path(log_path).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def main() -> int:
    argv = sys.argv[1:]
    if argv == ["--version"]:
        print("opencode 1.18.0")
        return 0
    if argv == ["run", "--help"]:
        print("--agent --format --dir --model --variant")
        return 0
    if not argv or argv[0] != "run":
        return 2

    config = json.loads(Path(os.environ["OPENCODE_CONFIG"]).read_text())
    agent_id = argv[argv.index("--agent") + 1]
    selected = config["agent"][agent_id]
    if config["default_agent"] != agent_id or selected["mode"] != "primary":
        return 3
    if selected["prompt"] != "External AgentField PM profile instructions.":
        return 4

    _record({"argv": argv, "config": config, "prompt": argv[-1]})
    result = {
        "validated_description": "external profile fixture",
        "acceptance_criteria": ["the profile is selected"],
        "must_have": ["the role prompt is preserved"],
        "nice_to_have": [],
        "out_of_scope": [],
    }
    print(json.dumps({"type": "text", "part": {"text": json.dumps(result)}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
''',
        encoding="utf-8",
    )
    fake_opencode.chmod(0o755)

    log_path = tmp_path / "opencode.jsonl"
    monkeypatch.setenv("AGENTFIELD_OPENCODE_PROFILE_FILE", str(profile_path))
    monkeypatch.setenv("FAKE_OPENCODE_LOG", str(log_path))

    harness_config = HarnessConfig(
        provider="opencode",
        opencode_bin=str(fake_opencode),
    )
    monkeypatch.setattr(app_module.app, "harness_config", harness_config)
    monkeypatch.setattr(app_module.app, "_harness_runner", None)

    observed_harness_calls: list[dict[str, object]] = []

    async def traced_harness(prompt: str, **kwargs: object):
        observed_harness_calls.append(dict(kwargs))
        return await app_module.app.harness(prompt, **kwargs)

    # Use a fresh role-facing proxy rather than relying on whichever router a
    # preceding module-isolation test left attached to the process-wide app.
    role_router = SimpleNamespace(
        harness=traced_harness,
        note=MagicMock(),
        agentfield_server="http://localhost:9999",
    )
    monkeypatch.setattr(pipeline, "router", role_router)

    real_product_manager = getattr(
        pipeline.run_product_manager,
        "_original_func",
        pipeline.run_product_manager,
    )
    with (
        patch("swe_af.hitl.build_hax_client_from_env", return_value=None),
        patch("swe_af.hitl.approval_webhook_url", return_value=None),
    ):
        result = await real_product_manager(
            goal="Exercise the external profile path",
            repo_path=str(tmp_path),
            model="openrouter/role-model#role-variant",
            max_turns=2,
            permission_mode="auto",
            ai_provider="open_code",
        )

    assert result["validated_description"] == "external profile fixture"
    assert observed_harness_calls
    assert observed_harness_calls[0]["profile"] == ProfileId("swe_af.main.pm")
    assert observed_harness_calls[0]["system_prompt"] == SYSTEM_PROMPT

    records = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    run_record = next(record for record in records if record["argv"][0] == "run")
    argv = run_record["argv"]
    assert argv[argv.index("--agent") + 1] == "swe_af.main.pm"
    assert argv[argv.index("-m") + 1] == "openrouter/role-model"
    assert argv[argv.index("--variant") + 1] == "role-variant"
    assert run_record["config"]["agent"]["swe_af.main.pm"]["prompt"] == (
        "External AgentField PM profile instructions."
    )

    effective_prompt = run_record["prompt"]
    assert effective_prompt.startswith("SYSTEM INSTRUCTIONS:\n" + SYSTEM_PROMPT)
    assert "\n---\n\nUSER REQUEST:\n" in effective_prompt
    assert "## Goal\nExercise the external profile path" in effective_prompt
    assert "External AgentField PM profile instructions." not in effective_prompt

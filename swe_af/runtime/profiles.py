"""SWE-AF's semantic role-to-harness profile registry.

The registry names application roles; it does not describe how a provider
implements a profile.  AgentField owns provider configuration, permissions,
isolation, and process policy.  Keeping those concerns out of this module
leaves the ``profile`` value an opaque ``ProfileId`` at the harness boundary.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from agentfield.types import ProfileId

from swe_af.runtime.providers import normalize_runtime_provider


class ProfileLookupError(KeyError):
    """Raised when a profile-managed direct path has no valid registry entry."""


@dataclass(frozen=True, slots=True)
class ProfileEntry:
    """Immutable audit metadata for one role or delegation alias.

    ``tool_metadata`` records the existing harness intent for inventory tests;
    it is not an OpenCode permission object.  The ``model_source`` and
    ``prompt_source`` fields point to existing SWE-AF inputs and deliberately
    contain no defaults or prompt content.
    """

    profile_id: ProfileId | None
    callable: str
    router: str
    area: str
    direct_harness: bool
    delegate_of: str | None
    source_file: str
    source_symbol: str
    prompt_source: str
    model_source: str
    schema: str | None
    tool_metadata: tuple[str, ...]
    policy_id: str
    source_call_index: int | None = None


_POLICY_ID: Final = "agentfield.autonomous"


def _direct(
    profile_id: str,
    callable_name: str,
    router: str,
    area: str,
    source_file: str,
    prompt_source: str,
    model_source: str,
    schema: str,
    tools: tuple[str, ...],
) -> ProfileEntry:
    return ProfileEntry(
        profile_id=ProfileId(profile_id),
        callable=callable_name,
        router=router,
        area=area,
        direct_harness=True,
        delegate_of=None,
        source_file=source_file,
        source_symbol=callable_name,
        prompt_source=prompt_source,
        model_source=model_source,
        schema=schema,
        tool_metadata=tools,
        policy_id=_POLICY_ID,
        source_call_index=1,
    )


def _non_harness(
    profile_key: str,
    callable_name: str,
    area: str,
    source_file: str,
) -> tuple[str, ProfileEntry]:
    return profile_key, ProfileEntry(
        profile_id=None,
        callable=callable_name,
        router="swe-planner",
        area=area,
        direct_harness=False,
        delegate_of=None,
        source_file=source_file,
        source_symbol=callable_name,
        prompt_source="",
        model_source="",
        schema=None,
        tool_metadata=(),
        policy_id=_POLICY_ID,
        source_call_index=None,
    )


_DIRECT_ENTRIES: tuple[tuple[str, ProfileEntry], ...] = (
    (
        "swe_af.main.pm",
        _direct(
            "swe_af.main.pm",
            "run_product_manager",
            "swe-planner",
            "planning",
            "swe_af/reasoners/pipeline.py",
            "swe_af.prompts.product_manager",
            "BuildConfig.pm_model",
            "PRD",
            ("Read", "Write", "Glob", "Grep", "Bash"),
        ),
    ),
    (
        "swe_af.main.environment_scout",
        _direct(
            "swe_af.main.environment_scout",
            "run_environment_scout",
            "swe-planner",
            "planning",
            "swe_af/reasoners/pipeline.py",
            "swe_af.prompts.environment_scout",
            "BuildConfig.pm_model",
            "ScoutResult",
            ("Read", "Glob", "Grep", "Bash"),
        ),
    ),
    (
        "swe_af.main.architect",
        _direct(
            "swe_af.main.architect",
            "run_architect",
            "swe-planner",
            "planning",
            "swe_af/reasoners/pipeline.py",
            "swe_af.prompts.architect",
            "BuildConfig.architect_model",
            "Architecture",
            ("Read", "Write", "Glob", "Grep", "Bash"),
        ),
    ),
    (
        "swe_af.main.tech_lead",
        _direct(
            "swe_af.main.tech_lead",
            "run_tech_lead",
            "swe-planner",
            "planning",
            "swe_af/reasoners/pipeline.py",
            "swe_af.prompts.tech_lead",
            "BuildConfig.tech_lead_model",
            "ReviewResult",
            ("Read", "Write", "Glob", "Grep"),
        ),
    ),
    (
        "swe_af.main.sprint_planner",
        _direct(
            "swe_af.main.sprint_planner",
            "run_sprint_planner",
            "swe-planner",
            "planning",
            "swe_af/reasoners/pipeline.py",
            "swe_af.prompts.sprint_planner",
            "BuildConfig.sprint_planner_model",
            "SprintPlanOutput",
            ("Read", "Write", "Glob", "Grep"),
        ),
    ),
    (
        "swe_af.main.retry_advisor",
        _direct(
            "swe_af.main.retry_advisor",
            "run_retry_advisor",
            "swe-planner",
            "advisor",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.retry_advisor",
            "ExecutionConfig.retry_advisor_model",
            "RetryAdvice",
            ("Read", "Write", "Glob", "Grep", "Bash"),
        ),
    ),
    (
        "swe_af.main.issue_advisor",
        _direct(
            "swe_af.main.issue_advisor",
            "run_issue_advisor",
            "swe-planner",
            "advisor",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.issue_advisor",
            "ExecutionConfig.issue_advisor_model",
            "IssueAdvisorDecision",
            ("Read", "Write", "Glob", "Grep", "Bash"),
        ),
    ),
    (
        "swe_af.main.replanner",
        _direct(
            "swe_af.main.replanner",
            "run_replanner",
            "swe-planner",
            "advisor",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.replanner",
            "ExecutionConfig.replan_model",
            "ReplanDecision",
            ("Read", "Write", "Glob", "Grep", "Bash"),
        ),
    ),
    (
        "swe_af.main.issue_writer",
        _direct(
            "swe_af.main.issue_writer",
            "run_issue_writer",
            "swe-planner",
            "advisor",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.issue_writer",
            "ExecutionConfig.issue_writer_model",
            "IssueWriterOutput",
            ("Read", "Write", "Glob", "Grep"),
        ),
    ),
    (
        "swe_af.main.verifier",
        _direct(
            "swe_af.main.verifier",
            "run_verifier",
            "swe-planner",
            "advisor",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.verifier",
            "ExecutionConfig.verifier_model",
            "VerificationResult",
            ("Read", "Write", "Glob", "Grep", "Bash"),
        ),
    ),
    (
        "swe_af.main.git_init",
        _direct(
            "swe_af.main.git_init",
            "run_git_init",
            "swe-planner",
            "gitops",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.git_init",
            "ExecutionConfig.git_model",
            "GitInitResult",
            ("Bash", "Write"),
        ),
    ),
    (
        "swe_af.main.workspace_setup",
        _direct(
            "swe_af.main.workspace_setup",
            "run_workspace_setup",
            "swe-planner",
            "gitops",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.workspace",
            "ExecutionConfig.git_model",
            "WorkspaceSetupResult",
            ("Bash", "Write"),
        ),
    ),
    (
        "swe_af.main.merger",
        _direct(
            "swe_af.main.merger",
            "run_merger",
            "swe-planner",
            "gitops",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.merger",
            "ExecutionConfig.merger_model",
            "MergeResult",
            ("Bash", "Read", "Write", "Glob", "Grep"),
        ),
    ),
    (
        "swe_af.main.integration_tester",
        _direct(
            "swe_af.main.integration_tester",
            "run_integration_tester",
            "swe-planner",
            "gitops",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.integration_tester",
            "ExecutionConfig.integration_tester_model",
            "IntegrationTestResult",
            ("Bash", "Read", "Write", "Glob", "Grep"),
        ),
    ),
    (
        "swe_af.main.workspace_cleanup",
        _direct(
            "swe_af.main.workspace_cleanup",
            "run_workspace_cleanup",
            "swe-planner",
            "gitops",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.workspace",
            "ExecutionConfig.git_model",
            "WorkspaceCleanupResult",
            ("Bash", "Write"),
        ),
    ),
    (
        "swe_af.main.coder",
        _direct(
            "swe_af.main.coder",
            "run_coder",
            "swe-planner",
            "coding",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.coder",
            "ExecutionConfig.coder_model",
            "CoderResult",
            ("Read", "Write", "Edit", "Bash", "Glob", "Grep"),
        ),
    ),
    (
        "swe_af.main.qa",
        _direct(
            "swe_af.main.qa",
            "run_qa",
            "swe-planner",
            "coding",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.qa",
            "ExecutionConfig.qa_model",
            "QAResult",
            ("Read", "Write", "Edit", "Bash", "Glob", "Grep"),
        ),
    ),
    (
        "swe_af.main.code_reviewer",
        _direct(
            "swe_af.main.code_reviewer",
            "run_code_reviewer",
            "swe-planner",
            "coding",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.code_reviewer",
            "ExecutionConfig.code_reviewer_model",
            "CodeReviewResult",
            ("Read", "Write", "Glob", "Grep", "Bash"),
        ),
    ),
    (
        "swe_af.main.fix_issues",
        _direct(
            "swe_af.main.fix_issues",
            "generate_fix_issues",
            "swe-planner",
            "advisor",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.fix_generator",
            "caller: verifier_model",
            "FixGeneratorOutput",
            ("Read", "Write", "Glob", "Grep", "Bash"),
        ),
    ),
    (
        "swe_af.main.repo_finalize",
        _direct(
            "swe_af.main.repo_finalize",
            "run_repo_finalize",
            "swe-planner",
            "gitops",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.repo_finalize",
            "ExecutionConfig.git_model",
            "RepoFinalizeResult",
            ("Bash", "Read", "Write", "Glob", "Grep"),
        ),
    ),
    (
        "swe_af.main.github_pr",
        _direct(
            "swe_af.main.github_pr",
            "run_github_pr",
            "swe-planner",
            "gitops",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.github_pr",
            "ExecutionConfig.git_model",
            "GitHubPRResult",
            ("Bash", "Write"),
        ),
    ),
    (
        "swe_af.main.ci_fixer",
        _direct(
            "swe_af.main.ci_fixer",
            "run_ci_fixer",
            "swe-planner",
            "ci",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.ci_fixer",
            "caller: ci_fixer_model or coder_model",
            "CIFixResult",
            ("Bash", "Read", "Edit", "Write", "Glob", "Grep"),
        ),
    ),
    (
        "swe_af.main.pr_resolver",
        _direct(
            "swe_af.main.pr_resolver",
            "run_pr_resolver",
            "swe-planner",
            "ci",
            "swe_af/reasoners/execution_agents.py",
            "swe_af.prompts.pr_resolver",
            "caller: ci_fixer_model or coder_model",
            "PRResolveResult",
            ("Bash", "Read", "Edit", "Write", "Glob", "Grep"),
        ),
    ),
)


_DIRECT_BY_KEY: dict[str, ProfileEntry] = dict(_DIRECT_ENTRIES)


_NON_HARNESS_ENTRIES: tuple[tuple[str, ProfileEntry], ...] = (
    _non_harness(
        "swe_af.main.qa_synthesizer",
        "run_qa_synthesizer",
        "coding",
        "swe_af/reasoners/execution_agents.py",
    ),
    _non_harness(
        "swe_af.main.ci_watcher",
        "run_ci_watcher",
        "ci",
        "swe_af/reasoners/execution_agents.py",
    ),
)


def _alias(
    profile_key: str,
    callable_name: str,
    delegate_of: str,
    router: str,
    area: str,
    source_file: str,
    direct_harness: bool = False,
) -> tuple[str, ProfileEntry]:
    target = _DIRECT_BY_KEY.get(delegate_of) or dict(_NON_HARNESS_ENTRIES).get(delegate_of)
    if target is None:
        raise RuntimeError(f"profile alias target is not registered: {delegate_of}")
    return profile_key, ProfileEntry(
        profile_id=target.profile_id,
        callable=callable_name,
        router=router,
        area=area,
        direct_harness=direct_harness,
        delegate_of=delegate_of,
        source_file=source_file,
        source_symbol=callable_name,
        prompt_source=target.prompt_source,
        model_source=target.model_source,
        schema=target.schema,
        tool_metadata=target.tool_metadata,
        policy_id=target.policy_id,
        source_call_index=1 if direct_harness else None,
    )


_ALIAS_ENTRIES: tuple[tuple[str, ProfileEntry], ...] = (
    _alias(
        "swe_af.fast.run_git_init",
        "run_git_init",
        "swe_af.main.git_init",
        "swe-fast",
        "gitops",
        "swe_af/fast/__init__.py",
    ),
    _alias(
        "swe_af.fast.run_coder",
        "run_coder",
        "swe_af.main.coder",
        "swe-fast",
        "coding",
        "swe_af/fast/__init__.py",
    ),
    _alias(
        "swe_af.fast.run_verifier",
        "run_verifier",
        "swe_af.main.verifier",
        "swe-fast",
        "advisor",
        "swe_af/fast/__init__.py",
    ),
    _alias(
        "swe_af.fast.run_repo_finalize",
        "run_repo_finalize",
        "swe_af.main.repo_finalize",
        "swe-fast",
        "gitops",
        "swe_af/fast/__init__.py",
    ),
    _alias(
        "swe_af.fast.run_github_pr",
        "run_github_pr",
        "swe_af.main.github_pr",
        "swe-fast",
        "gitops",
        "swe_af/fast/__init__.py",
    ),
    _alias(
        "swe_af.fast.run_ci_watcher",
        "run_ci_watcher",
        "swe_af.main.ci_watcher",
        "swe-fast",
        "ci",
        "swe_af/fast/__init__.py",
    ),
    _alias(
        "swe_af.fast.run_ci_fixer",
        "run_ci_fixer",
        "swe_af.main.ci_fixer",
        "swe-fast",
        "ci",
        "swe_af/fast/__init__.py",
    ),
    _alias(
        "swe_af.fast.execute_tasks",
        "fast_execute_tasks",
        "swe_af.main.coder",
        "swe-fast",
        "fast",
        "swe_af/fast/executor.py",
    ),
    _alias(
        "swe_af.fast.verify",
        "fast_verify",
        "swe_af.main.verifier",
        "swe-fast",
        "fast",
        "swe_af/fast/verifier.py",
    ),
    _alias(
        "swe_af.compat.replanner",
        "invoke_replanner",
        "swe_af.main.replanner",
        "compat",
        "advisor",
        "swe_af/execution/_replanner_compat.py",
        direct_harness=True,
    ),
)


_FAST_PLANNER_ENTRY = (
    "swe_af.fast.plan_tasks",
    _direct(
        "swe_af.fast.plan_tasks",
        "fast_plan_tasks",
        "swe-fast",
        "fast",
        "swe_af/fast/planner.py",
        "swe_af.fast.prompts",
        "FastBuildConfig.pm_model",
        "FastPlanResult",
        (),
    ),
)


PROFILE_REGISTRY: Final[Mapping[str, ProfileEntry]] = MappingProxyType(
    dict(_DIRECT_ENTRIES + _NON_HARNESS_ENTRIES + _ALIAS_ENTRIES + (_FAST_PLANNER_ENTRY,))
)

# Canonical profile entries are the only entries that own a profile policy.
# Aliases intentionally reuse their target's ID and must not add a policy.
CANONICAL_PROFILE_ENTRIES: Final[tuple[ProfileEntry, ...]] = tuple(
    entry for _, entry in _DIRECT_ENTRIES if entry.profile_id is not None
) + (_FAST_PLANNER_ENTRY[1],)

DIRECT_PROFILE_KEYS: Final[tuple[str, ...]] = tuple(
    key for key, entry in PROFILE_REGISTRY.items() if entry.direct_harness
)

ALIASES: Final[tuple[str, ...]] = tuple(
    key for key, entry in PROFILE_REGISTRY.items() if entry.delegate_of is not None
)

_CALLABLE_KEYS: Mapping[str, str] = MappingProxyType(
    {
        entry.callable: key
        for key, entry in PROFILE_REGISTRY.items()
        if entry.direct_harness
    }
)


def _entry_for(key: str) -> ProfileEntry:
    """Resolve a registry key or an unambiguous direct callable name."""
    entry = PROFILE_REGISTRY.get(key)
    if entry is None:
        canonical_key = _CALLABLE_KEYS.get(key)
        if canonical_key is not None:
            entry = PROFILE_REGISTRY[canonical_key]
    if entry is None:
        raise ProfileLookupError(f"no SWE-AF profile registry entry for {key!r}")

    seen: set[str] = set()
    current_key = key
    while entry.delegate_of is not None:
        if current_key in seen:
            raise ProfileLookupError(f"cyclic SWE-AF profile alias at {key!r}")
        seen.add(current_key)
        current_key = entry.delegate_of
        entry = PROFILE_REGISTRY.get(current_key)
        if entry is None:
            raise ProfileLookupError(
                f"SWE-AF profile alias {key!r} targets missing entry {current_key!r}"
            )
    return entry


def profile_for(callable_key: str, ai_provider: str) -> ProfileId | None:
    """Return the profile for an OpenCode direct path, or ``None`` otherwise.

    Lookup is intentionally performed only after the existing runtime is
    normalized to OpenCode.  Claude Code and Codex therefore retain their
    profileless path.  Unknown OpenCode paths fail closed, while registered
    non-harness paths intentionally return ``None`` because they never cross a
    harness boundary; there is no fallback profile in this module.
    """
    runtime = normalize_runtime_provider(ai_provider)
    if runtime != "open_code":
        return None

    entry = _entry_for(callable_key)
    if not entry.direct_harness:
        return None
    if entry.profile_id is None:
        raise ProfileLookupError(
            f"profile-managed OpenCode path {callable_key!r} has no direct profile"
        )
    return entry.profile_id


__all__ = [
    "ALIASES",
    "CANONICAL_PROFILE_ENTRIES",
    "DIRECT_PROFILE_KEYS",
    "PROFILE_REGISTRY",
    "ProfileEntry",
    "ProfileLookupError",
    "profile_for",
]

"""Prompt-injection 的第一层防护：规则检测、上下文裁剪与可选脱敏。"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class GuardResult:
    # True 只表示可直接进入主 Agent；review 不得直通主模型。
    allowed: bool
    risk_score: int
    risk_level: str  # allow | review | block
    reasons: list[str]
    sanitized_text: str
    redactions: list[str]
    # 仅包含不可信证据，便于直接作为 LLM 的 user 消息。
    sanitized_evidence: str = ""
    # 分离“能否分析证据”和“能否自动执行工具”。保留 allowed 兼容旧编排代码。
    analysis_allowed: bool = True
    tool_execution_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PromptInjectionGuard:
    """对不可信消息和告警字段进行提示词攻击筛查。

    ``analysisInfo`` 是历史模型输出，默认不进入下一模型上下文，以减少污染、
    泄漏和 token 浪费。该组件只作第一层规则判定；``review`` 应交给安全模型
    二次判定，不能直接送入主 Agent。
    """

    _SKIP_FIELDS = frozenset({"analysisInfo", "think", "reasoning", "chain_of_thought"})
    _INVISIBLE = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
    _SPACE = re.compile(r"\s+")
    _RULES: tuple[tuple[str, int, re.Pattern[str]], ...] = (
        ("instruction override", 45, re.compile(
            r"(?:ignore|disregard|override|bypass|forget).{0,24}(?:previous|all|system).{0,16}(?:instruction|prompt|rule)|"
            r"(?:忽略|无视|忘记|覆盖|绕过|跳过).{0,16}(?:系统|之前|上文|所有).{0,12}(?:指令|提示|规则)", re.I)),
        ("role hijacking", 35, re.compile(
            r"(?:you are now|act as|pretend to be).{0,40}(?:system|developer|admin)|"
            r"(?:你现在是|扮演|假装).{0,24}(?:系统|开发者|管理员)", re.I)),
        ("system prompt exfiltration", 35, re.compile(
            r"(?:reveal|show|print|repeat|leak).{0,36}(?:system prompt|hidden prompt|instructions)|"
            r"(?:告诉我|输出|打印|重复|泄露).{0,24}(?:系统提示词|隐藏提示|内部指令|内部规则)", re.I)),
        # 只把“让 Agent 执行”的祈使句视为可疑，避免误报“分析攻击者执行 PowerShell”。
        ("dangerous tool execution request", 40, re.compile(
            r"(?:please|you|agent|now).{0,24}(?:run|execute|call).{0,24}(?:shell|powershell|cmd|sql|tool)|"
            r"(?:请|让你|你现在|agent).{0,12}(?:执行|运行|调用).{0,24}(?:命令|脚本|shell|powershell|cmd|sql|工具)", re.I)),
        ("obfuscation bypass request", 25, re.compile(
            r"(?:base64|rot13|unicode).{0,36}(?:decode|bypass|ignore|inject)|"
            r"(?:编码|混淆).{0,24}(?:绕过|忽略|注入|解码|还原)", re.I)),
    )
    # 同时支持 HTTP Header 和 JSON："Authorization": "Bearer xxx"
    _BEARER_RE = re.compile(
        r'''(?i)(["']?authorization["']?\s*[:=]\s*["']?\s*bearer\s+)([^"'\s,;}]+)'''
    )
    _SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("credential/token", re.compile(r'''(?i)(["']?(?:api[_ -]?key|refresh[_ -]?token|access[_ -]?token|id[_ -]?token|auth[_ -]?token|client[_ -]?secret|token|password|passwd|secret)["']?\s*[:=]\s*["']?)([^"'\s,;}]+)''')),
        ("ID number", re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")),
        ("phone number", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    )
    _BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){4,}(?:==|=)?(?![A-Za-z0-9+/=])")

    def __init__(self, block_score: int = 60, review_score: int = 30, max_chars: int = 12000):
        if not 0 <= review_score <= block_score <= 100:
            raise ValueError("scores must satisfy 0 <= review_score <= block_score <= 100")
        self.block_score = block_score
        self.review_score = review_score
        self.max_chars = max_chars

    @classmethod
    def _flatten(cls, value: Any, prefix: str = "") -> Iterable[tuple[str, str]]:
        if isinstance(value, Mapping):
            for key, item in value.items():
                if str(key) in cls._SKIP_FIELDS:
                    continue
                child_prefix = f"{prefix}.{key}" if prefix else str(key)
                yield from cls._flatten(item, child_prefix)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                yield from cls._flatten(item, f"{prefix}[{index}]")
        elif value is not None:
            string = str(value)
            if string.strip():
                yield prefix, string

    _SENSITIVE_KEY_PARTS = frozenset({
        "password", "passwd", "apikey", "token", "accesstoken", "refreshtoken",
        "idtoken", "authtoken", "secret", "clientsecret", "authorization", "bearer",
    })

    @classmethod
    def _format_pairs(cls, pairs: list[tuple[str, str]], redact_sensitive: bool) -> tuple[str, list[str]]:
        lines: list[str] = []
        redactions: list[str] = []
        for key, value in pairs:
            masked = value
            leaf = re.sub(r"\[\d+\]", "", key).split(".")[-1].lower()
            compact_leaf = re.sub(r"[^a-z]", "", leaf)
            if redact_sensitive and compact_leaf in cls._SENSITIVE_KEY_PARTS:
                redactions.append("credential/token")
                bearer = re.match(r"(?is)^(\s*bearer\s+).+$", value)
                masked = (bearer.group(1) + "[REDACTED]") if bearer else "[REDACTED]"
            lines.append(f"[{key}] {masked}")
        return "\n".join(lines), sorted(set(redactions))

    @classmethod
    def _prepare_input(
        cls,
        data: Any,
        trusted_instruction: str | None = None,
        *,
        redact_sensitive: bool = True,
        trust_message_roles: bool = False,
    ) -> tuple[str, str, list[str], str]:
        """返回展示文本和实际扫描文本。

        ``trusted_instruction`` 只能由编排器通过带外参数提供，不参与攻击判定。
        输入 JSON 中自称为 instruction/system 的字段一律不自动信任。对于 messages，
        默认所有角色都扫描；仅在编排器显式设置 ``trust_message_roles=True`` 时，
        system/developer 角色才视为可信。
        """
        if trusted_instruction is not None:
            pairs = [("input", data)] if isinstance(data, str) else list(cls._flatten(data))
            evidence, redactions = cls._format_pairs(pairs, redact_sensitive)
            raw_evidence = "\n".join(f"[{key}] {value}" for key, value in pairs)
            display = f"[trusted_instruction] {trusted_instruction}\n[untrusted_data]\n{evidence}"
            return display, raw_evidence, redactions, evidence

        pairs = list(cls._flatten(data))
        display, redactions = cls._format_pairs(pairs, redact_sensitive)
        scan_pairs = pairs
        if trust_message_roles and isinstance(data, Mapping) and isinstance(data.get("messages"), list):
            trusted_indexes = {
                index for index, message in enumerate(data["messages"])
                if isinstance(message, Mapping)
                and str(message.get("role", "user")).lower() in {"system", "developer"}
            }
            scan_pairs = [
                (key, value) for key, value in pairs
                if not any(key.startswith(f"messages[{index}]") for index in trusted_indexes)
            ]
        scan_text = "\n".join(f"[{key}] {value}" for key, value in scan_pairs)
        return display, scan_text, redactions, display

    @classmethod
    def _normalise(cls, text: str) -> tuple[str, str, str]:
        normal = cls._INVISIBLE.sub("", unicodedata.normalize("NFKC", text))
        compact = cls._SPACE.sub("", normal)
        # 仅用于检测，不改变真正传给安全分析模型的证据文本。
        punctuation_compact = cls._remove_punctuation_and_symbols(normal)
        return normal, compact, punctuation_compact

    @staticmethod
    def _remove_punctuation_and_symbols(text: str) -> str:
        """删除 Unicode 标点/符号，仅用于检测副本，不改变证据原文。"""
        return "".join(
            char for char in text
            if not char.isspace() and unicodedata.category(char)[0] not in {"P", "S"}
        )

    @classmethod
    def _decoded_base64(cls, text: str) -> Iterable[str]:
        for token in cls._BASE64_TOKEN.findall(text):
            if len(token) > 4096:
                continue
            try:
                decoded = base64.b64decode(token, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                continue
            if decoded.isprintable() or "\n" in decoded:
                yield decoded

    def _sanitize(self, text: str, redact_sensitive: bool, initial_redactions: Iterable[str] = ()) -> tuple[str, list[str]]:
        if not redact_sensitive:
            return text[: self.max_chars], []
        redactions: list[str] = list(initial_redactions)

        def bearer_replacement(match: re.Match[str]) -> str:
            redactions.append("credential/token")
            return match.group(1) + "[REDACTED]"

        out = self._BEARER_RE.sub(bearer_replacement, text)
        for label, pattern in self._SECRET_RULES:
            def replacement(match: re.Match[str], category: str = label) -> str:
                redactions.append(category)
                return match.group(1) + "[REDACTED]" if match.lastindex else "[REDACTED]"
            out = pattern.sub(replacement, out)
        return out[: self.max_chars], sorted(set(redactions))

    def analyze(
        self,
        data: Any,
        *,
        redact_sensitive: bool = True,
        trusted_instruction: str | None = None,
        trust_message_roles: bool = False,
    ) -> GuardResult:
        if isinstance(data, str) and trusted_instruction is None:
            text, scan_input, field_redactions, evidence_text = f"[input] {data}", data, [], f"[input] {data}"
        else:
            text, scan_input, field_redactions, evidence_text = self._prepare_input(
                data,
                trusted_instruction,
                redact_sensitive=redact_sensitive,
                trust_message_roles=trust_message_roles,
            )
        normal, compact, punctuation_compact = self._normalise(scan_input)
        decoded = list(self._decoded_base64(normal))
        scan_texts = [normal, compact, punctuation_compact, *decoded]
        score = 0
        reasons: list[str] = []
        for name, weight, rule in self._RULES:
            if any(rule.search(candidate) for candidate in scan_texts):
                score += weight
                reasons.append(name)
        if decoded and any(self._RULES[0][2].search(candidate) for candidate in decoded):
            reasons.append("base64 encoded injection")
        # trusted_instruction 只用于编排上下文，不混入下游证据文本。
        sanitized, redactions = self._sanitize(evidence_text, redact_sensitive, field_redactions)
        if redactions:
            reasons.append("sensitive values redacted")
            score += 10
        score = min(score, 100)
        level = "block" if score >= self.block_score else ("review" if score >= self.review_score else "allow")
        return GuardResult(
            level == "allow",
            score,
            level,
            reasons,
            sanitized,
            redactions,
            sanitized_evidence=sanitized,
            analysis_allowed=True,
            tool_execution_allowed=level == "allow",
        )


def analyze_dataset(records: list[Any], guard: PromptInjectionGuard | None = None) -> list[dict[str, Any]]:
    guard = guard or PromptInjectionGuard()
    return [guard.analyze(record).to_dict() for record in records]

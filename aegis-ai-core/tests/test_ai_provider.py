"""
test_ai_provider.py - AIAnalyzer 多提供商支持单元测试

验证 AIAnalyzer._resolve_provider 的提供商自动推断逻辑：
- 默认 DeepSeek 行为
- 显式 AI_PROVIDER 环境变量（ollama / openai / custom）
- OLLAMA_BASE_URL 自动推断
- OPENAI_API_KEY 自动推断（仅在无 DeepSeek Key 时）
- 构造函数参数覆盖
"""

import json

import pytest

# 清理测试中可能影响结果的环境变量的辅助函数
_PROVIDER_ENV_KEYS = [
    "AI_PROVIDER",
    "DEEPSEEK_API_KEY",
    "DEEPSEEK_BASE_URL",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OLLAMA_BASE_URL",
    "OLLAMA_MODEL",
    "AI_BASE_URL",
    "AI_API_KEY",
    "AI_MODEL",
    "AI_PROVIDER_FALLBACK_ORDER",
    "OLLAMA_API_KEY",
]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """每个测试前清理所有提供商相关环境变量。"""
    for key in _PROVIDER_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    yield


from src.ai import LLMGateway, LLMRequest, LLMResponse
from src.scanner.ai_analyzer import AIAnalysisResult, AIAnalyzer, build_local_fix_analysis


class TestResolveProviderDefaults:
    def test_default_is_ollama(self):
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert provider == "ollama"
        assert "11434" in base
        assert key == "ollama"
        assert model == "llama3"

    def test_deepseek_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-test-key")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert provider == "deepseek"
        assert key == "ds-test-key"

    def test_constructor_api_key_overrides_env(self, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-env-key")
        provider, key, base, model = AIAnalyzer._resolve_provider("explicit-key", None, None)
        assert key == "explicit-key"

    def test_constructor_model_override(self):
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, "deepseek-reasoner")
        assert model == "deepseek-reasoner"


class TestOllamaProvider:
    def test_explicit_ollama_provider(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "ollama")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert provider == "ollama"
        assert "11434" in base  # default Ollama port
        assert key == "ollama"  # sentinel value, no real key needed

    def test_ollama_via_base_url(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert provider == "ollama"
        assert base == "http://localhost:11434/v1"

    def test_ollama_custom_base_url(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "ollama")
        monkeypatch.setenv("OLLAMA_BASE_URL", "http://myserver:8080/v1")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert base == "http://myserver:8080/v1"

    def test_ollama_custom_model(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "ollama")
        monkeypatch.setenv("OLLAMA_MODEL", "mistral")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert model == "mistral"

    def test_ollama_enabled_without_api_key(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "ollama")
        analyzer = AIAnalyzer(enabled=True)
        assert analyzer.enabled is True
        assert analyzer.provider == "ollama"


class TestOpenAIProvider:
    def test_explicit_openai_provider(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert provider == "openai"
        assert "openai.com" in base
        assert model == "gpt-4o-mini"

    def test_openai_fallback_when_no_deepseek_key(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-only")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert provider == "openai"
        assert key == "sk-openai-only"

    def test_deepseek_wins_when_both_keys_set(self, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-key")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-key")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert provider == "deepseek"

    def test_openai_custom_base(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://custom.openai.proxy/v1")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert base == "https://custom.openai.proxy/v1"


class TestCustomProvider:
    def test_custom_provider(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "custom")
        monkeypatch.setenv("AI_BASE_URL", "https://my-llm.example.com/v1")
        monkeypatch.setenv("AI_API_KEY", "custom-key")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert provider == "custom"
        assert base == "https://my-llm.example.com/v1"
        assert key == "custom-key"


class TestAnalyzerInit:
    def test_explicit_remote_provider_disabled_without_key(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "deepseek")
        analyzer = AIAnalyzer(enabled=True)
        # Remote providers still require credentials.
        assert analyzer.enabled is False

    def test_explicit_remote_provider_without_key_returns_structured_config_error(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "deepseek")
        analyzer = AIAnalyzer(enabled=True)
        result = analyzer.analyze_finding(
            {
                "type": "SQL_INJECTION",
                "severity": "High",
                "line": 12,
                "details": "Potential SQL injection",
                "file": "app.js",
            }
        )
        assert result.error_code == "provider_not_configured"
        assert result.error_message is not None
        assert "provider" in result.error_message.lower()

    def test_default_ollama_provider_is_enabled_without_key(self):
        analyzer = AIAnalyzer(enabled=True)
        assert analyzer.enabled is True
        assert analyzer.provider == "ollama"

    def test_enabled_with_deepseek_key(self, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-key")
        analyzer = AIAnalyzer(enabled=True)
        assert analyzer.enabled is True
        assert analyzer.provider == "deepseek"

    def test_provider_logged(self, monkeypatch, caplog):
        monkeypatch.setenv("AI_PROVIDER", "ollama")
        import logging

        with caplog.at_level(logging.INFO, logger="src.scanner.ai_analyzer"):
            AIAnalyzer(enabled=True)
        assert "ollama" in caplog.text.lower()


class TestAiAnalysisCache:
    def test_cache_is_bound_to_file_and_source_context(self, monkeypatch):
        analyzer = AIAnalyzer(api_key="test-key", enabled=True)
        calls: list[tuple[str, str]] = []

        def fake_call_ai_analysis(finding, rich_ctx=None, language=None):
            calls.append((finding.get("file", ""), (rich_ctx or {}).get("vuln_snippet", "")))
            return AIAnalysisResult(
                is_true_positive=True,
                confidence=0.91,
                risk_level="High",
                explanation=f"analysis {len(calls)} for {finding.get('file')}",
                fix_suggestion="Use a parameterized query",
                requires_review=False,
                fixed_code=f"fixed {len(calls)}",
                fix_start_line=finding.get("line"),
                fix_end_line=finding.get("line"),
            )

        monkeypatch.setattr(analyzer, "_call_ai_analysis", fake_call_ai_analysis)

        finding = {
            "type": "SQL_INJECTION",
            "severity": "High",
            "line": 2,
            "details": "Potential SQL injection in query execution",
        }

        first = analyzer.analyze_finding(
            {**finding, "file": "users.py", "language": "python"},
            language="python",
            source_code='name = request.args["name"]\nquery = "SELECT " + name\n',
        )
        second = analyzer.analyze_finding(
            {**finding, "file": "orders.py", "language": "python"},
            language="python",
            source_code='order = request.args["order"]\nquery = "SELECT " + order\n',
        )
        repeated_second = analyzer.analyze_finding(
            {**finding, "file": "orders.py", "language": "python"},
            language="python",
            source_code='order = request.args["order"]\nquery = "SELECT " + order\n',
        )

        assert first.fixed_code == "fixed 1"
        assert second.fixed_code == "fixed 2"
        assert repeated_second is second
        assert len(calls) == 2


class TestGatewayIntegration:
    def test_analyzer_uses_registered_provider_without_call_path_changes(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "fake")

        class FakeProvider:
            name = "fake"
            default_model = "fake-model"
            supports_streaming = False

            def is_configured(self):
                return True

            def generate(self, request: LLMRequest) -> LLMResponse:
                assert request.messages[-1]["role"] == "user"
                return LLMResponse(
                    content=json.dumps(
                        {
                            "is_false_positive": False,
                            "confidence": 0.93,
                            "risk_level": "High",
                            "explanation": "Use parameters.",
                            "fixed_code": "cursor.execute(query, (user_id,))",
                            "fix_start_line": 10,
                            "fix_end_line": 10,
                        }
                    ),
                    provider="fake",
                    model="fake-model",
                )

        analyzer = AIAnalyzer(enabled=True, llm_gateway=LLMGateway([FakeProvider()]))
        result = analyzer.analyze_finding(
            {
                "type": "SQL_INJECTION",
                "severity": "High",
                "line": 10,
                "start_line": 10,
                "end_line": 10,
                "details": "Potential SQL injection",
                "file": "app.py",
                "language": "python",
            },
            language="python",
            source_code='query = "SELECT * FROM users WHERE id = " + user_id\ncursor.execute(query)\n',
        )

        assert result.error_code is None
        assert result.fixed_code == "cursor.execute(query, (user_id,))"
        assert result.requires_review is False


class TestAiResponseErrors:
    def test_parse_response_without_fixed_code_marks_no_applicable_fix(self):
        analyzer = AIAnalyzer(enabled=False)
        result = analyzer._parse_ai_response(
            '{"confidence": 0.88, "risk_level": "High", "explanation": "Needs review", "fix_description": "Manually parameterize the query"}',
            {"severity": "High", "start_line": 5, "end_line": 5},
        )
        assert result.fixed_code is None
        assert result.error_code == "no_applicable_fix"
        assert result.error_message is not None

    def test_parse_invalid_json_marks_provider_unavailable(self):
        analyzer = AIAnalyzer(enabled=False)
        result = analyzer._parse_ai_response(
            "definitely not json",
            {"severity": "High", "start_line": 2, "end_line": 2},
        )
        assert result.error_code == "provider_unavailable"
        assert result.error_message is not None

    def test_parse_response_accepts_code_alias_and_strips_markdown_fence(self):
        analyzer = AIAnalyzer(enabled=False)
        result = analyzer._parse_ai_response(
            json.dumps(
                {
                    "confidence": 0.91,
                    "risk_level": "High",
                    "explanation": "Bounded copy is required.",
                    "replacement_code": "```cpp\nstrncpy(name, src, sizeof(name) - 1);\n```",
                    "fix_start_line": 12,
                    "fix_end_line": 12,
                }
            ),
            {"severity": "High", "start_line": 10, "end_line": 10},
        )

        assert result.fixed_code == "strncpy(name, src, sizeof(name) - 1);"
        assert result.fix_start_line == 12
        assert result.fix_end_line == 12


class TestCppBufferOverflowAiFixFallback:
    def test_cpp_cin_char_array_gets_local_width_replacement_without_ai(self):
        analyzer = AIAnalyzer(enabled=False)
        source = """void loop() {
    char name[20] = {'\\0'};
    int time = 0;
    cin>>name>>time;
}
"""

        result = analyzer.analyze_finding(
            {
                "type": "BUFFER_OVERFLOW",
                "severity": "Critical",
                "line": 4,
                "start_line": 4,
                "end_line": 4,
                "details": "C/C++: cin 写入固定 char[20] 数组 `name`，未限制输入长度",
                "file": "test.cpp",
                "language": "cpp",
            },
            language="cpp",
            source_code=source,
        )

        assert result.error_code is None
        assert result.fixed_code == "    cin.width(sizeof(name));\n    cin >> name >> time;"
        assert result.requires_review is True

    def test_cpp_strcpy_member_array_gets_local_safe_replacement(self, monkeypatch):
        analyzer = AIAnalyzer(api_key="test-key", enabled=True)

        def no_ai_fix(finding, rich_ctx=None, language=None):
            return AIAnalysisResult(
                is_true_positive=True,
                confidence=0.4,
                risk_level="Critical",
                explanation="AI did not return code.",
                fix_suggestion=None,
                requires_review=True,
                fixed_code=None,
                fix_start_line=finding.get("line"),
                fix_end_line=finding.get("line"),
                error_code="no_applicable_fix",
                error_message="AI reviewed this finding but did not return a safe replacement.",
            )

        monkeypatch.setattr(analyzer, "_call_ai_analysis", no_ai_fix)
        source = """typedef struct PCB {
    char name[20];
} PCB, *pPCB;

void createProcess(pPCB newPcb, char *name) {
    strcpy(newPcb->name, name);
}
"""
        vuln_line = 6

        result = analyzer.analyze_finding(
            {
                "type": "BUFFER_OVERFLOW",
                "severity": "Critical",
                "line": vuln_line,
                "start_line": vuln_line,
                "end_line": vuln_line,
                "details": "C/C++: 发现 BUFFER_OVERFLOW 风险 - strcpy(newPcb->name,name);",
                "file": "test.cpp",
                "language": "cpp",
            },
            language="cpp",
            source_code=source,
        )

        assert result.error_code is None
        assert result.fixed_code == (
            "    strncpy(newPcb->name, name, sizeof(newPcb->name) - 1);\n"
            "    newPcb->name[sizeof(newPcb->name) - 1] = '\\0';"
        )
        assert result.fix_start_line == vuln_line
        assert result.fix_end_line == vuln_line
        assert result.requires_review is True

    def test_cpp_strcpy_member_array_accepts_wrapped_rule_id(self):
        source = """typedef struct PCB {
    char name[20];
} PCB, *pPCB;

void createProcess(pPCB newPcb, char *name) {
    strcpy(newPcb->name, name);
}
"""

        result = build_local_fix_analysis(
            {
                "type": "Aegis AI(BUFFER_OVERFLOW)",
                "severity": "Critical",
                "line": 6,
                "start_line": 6,
                "end_line": 6,
                "details": "C/C++: 发现 BUFFER_OVERFLOW 风险 - strcpy(newPcb->name,name);",
                "file": "test.cpp",
                "language": "cpp",
            },
            source,
            "cpp",
        )

        assert result is not None
        assert result.fixed_code == (
            "    strncpy(newPcb->name, name, sizeof(newPcb->name) - 1);\n"
            "    newPcb->name[sizeof(newPcb->name) - 1] = '\\0';"
        )

    def test_cpp_strcpy_pointer_destination_keeps_no_applicable_fix(self, monkeypatch):
        analyzer = AIAnalyzer(api_key="test-key", enabled=True)

        def no_ai_fix(finding, rich_ctx=None, language=None):
            return AIAnalysisResult(
                is_true_positive=True,
                confidence=0.4,
                risk_level="Critical",
                explanation="AI did not return code.",
                fix_suggestion=None,
                requires_review=True,
                fixed_code=None,
                fix_start_line=finding.get("line"),
                fix_end_line=finding.get("line"),
                error_code="no_applicable_fix",
                error_message="AI reviewed this finding but did not return a safe replacement.",
            )

        monkeypatch.setattr(analyzer, "_call_ai_analysis", no_ai_fix)
        source = """void copyName(char *dst, char *src) {
    strcpy(dst, src);
}
"""

        result = analyzer.analyze_finding(
            {
                "type": "BUFFER_OVERFLOW",
                "severity": "Critical",
                "line": 2,
                "start_line": 2,
                "end_line": 2,
                "details": "C/C++: 发现 BUFFER_OVERFLOW 风险 - strcpy(dst, src);",
                "file": "test.cpp",
                "language": "cpp",
            },
            language="cpp",
            source_code=source,
        )

        assert result.fixed_code is None
        assert result.error_code == "no_applicable_fix"

    def test_cpp_assignment_condition_gets_local_comparison_replacement_without_ai(self):
        analyzer = AIAnalyzer(enabled=False)
        source = """void check() {
    if(currentPcb->flag=1)
        return;
}
"""

        result = analyzer.analyze_finding(
            {
                "type": "ASSIGNMENT_IN_CONDITION",
                "severity": "Medium",
                "line": 2,
                "start_line": 2,
                "end_line": 2,
                "details": "C/C++: 条件表达式中出现赋值运算",
                "file": "test.cpp",
                "language": "cpp",
            },
            language="cpp",
            source_code=source,
        )

        assert result.error_code is None
        assert result.fixed_code == "    if(currentPcb->flag == 1)"

    def test_cpp_null_deref_gets_local_inner_guard_without_ai(self):
        analyzer = AIAnalyzer(enabled=False)
        source = """void schedule() {
    if(pReadyList!=NULL)
        pReadyList->head=pReadyList->head->next;
}
"""

        result = analyzer.analyze_finding(
            {
                "type": "NULL_DEREFERENCE",
                "severity": "High",
                "line": 3,
                "start_line": 3,
                "end_line": 3,
                "details": "C/C++: 只检查 `pReadyList` 后继续解引用 `pReadyList->head`",
                "file": "test.cpp",
                "language": "cpp",
            },
            language="cpp",
            source_code=source,
        )

        assert result.error_code is None
        assert result.fixed_code == (
            "        if (pReadyList->head != NULL) {\n            pReadyList->head=pReadyList->head->next;\n        }"
        )

    def test_cpp_lock_mismatch_gets_local_matching_leave_replacement_without_ai(self):
        analyzer = AIAnalyzer(enabled=False)
        source = """void schedule() {
    EnterCriticalSection(&cs_ReadyList);
    LeaveCriticalSection(&cs_SaveInfo);
}
"""

        result = analyzer.analyze_finding(
            {
                "type": "LOCK_MISMATCH",
                "severity": "High",
                "line": 3,
                "start_line": 3,
                "end_line": 3,
                "details": "C/C++: 第 2 行进入 `cs_ReadyList`，但这里释放 `cs_SaveInfo`，可能导致死锁",
                "file": "test.cpp",
                "language": "cpp",
            },
            language="cpp",
            source_code=source,
        )

        assert result.error_code is None
        assert result.fixed_code == "    LeaveCriticalSection(&cs_ReadyList);"

    def test_cpp_suspend_thread_gets_review_block_without_ai(self):
        analyzer = AIAnalyzer(enabled=False)
        source = """void schedule() {
    SuspendThread(runPCB->hThis);
}
"""

        result = analyzer.analyze_finding(
            {
                "type": "THREAD_LIFECYCLE_RISK",
                "severity": "High",
                "line": 2,
                "start_line": 2,
                "end_line": 2,
                "details": "C/C++: SuspendThread 可能在线程持锁时强制中断",
                "file": "test.cpp",
                "language": "cpp",
            },
            language="cpp",
            source_code=source,
        )

        assert result.error_code is None
        assert result.fixed_code is not None
        assert "Original unsafe call kept for review" in result.fixed_code
        assert "// SuspendThread(runPCB->hThis);" in result.fixed_code

    def test_cpp_terminate_thread_condition_gets_review_branch_without_ai(self):
        analyzer = AIAnalyzer(enabled=False)
        source = """void schedule() {
    if(!TerminateThread(runPCB->hThis,1))
    {
        return;
    }
}
"""

        result = analyzer.analyze_finding(
            {
                "type": "THREAD_LIFECYCLE_RISK",
                "severity": "High",
                "line": 2,
                "start_line": 2,
                "end_line": 2,
                "details": "C/C++: TerminateThread 可能在线程持锁时强制终止",
                "file": "test.cpp",
                "language": "cpp",
            },
            language="cpp",
            source_code=source,
        )

        assert result.error_code is None
        assert result.fixed_code is not None
        assert "Original unsafe condition kept for review" in result.fixed_code
        assert "// if(!TerminateThread(runPCB->hThis,1))" in result.fixed_code
        assert result.fixed_code.endswith("    if (true)")
        assert result.confidence < 0.5

    def test_buffer_overflow_prompt_includes_cpp_replacement_contract(self):
        analyzer = AIAnalyzer(enabled=False)
        prompt = analyzer._build_analysis_prompt(
            {
                "type": "BUFFER_OVERFLOW",
                "severity": "Critical",
                "line": 6,
                "start_line": 6,
                "end_line": 6,
                "details": "strcpy(newPcb->name, name)",
                "file": "test.cpp",
            },
            rich_ctx={"vuln_snippet": "    strcpy(newPcb->name, name);", "actual_start_line": 6},
            language="cpp",
        )

        assert '"fix_start_line": 6' in prompt
        assert "只包含 fix_start_line 到 fix_end_line 的替换代码" in prompt
        assert "strncpy(dst, src, sizeof(dst) - 1)" in prompt

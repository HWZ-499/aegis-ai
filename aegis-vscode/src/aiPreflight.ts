export function getAiConfigurationError(
  provider: string,
  env: NodeJS.ProcessEnv,
  aiEnabled: boolean,
): string | undefined {
  if (!aiEnabled) {
    return "Aegis AI fixes are disabled in settings (aegisAI.ai.enabled = false).";
  }

  switch ((provider || "deepseek").toLowerCase()) {
    case "deepseek":
      return env.DEEPSEEK_API_KEY ? undefined : "Missing DEEPSEEK_API_KEY for DeepSeek AI fixes.";
    case "openai":
      return env.OPENAI_API_KEY ? undefined : "Missing OPENAI_API_KEY for OpenAI AI fixes.";
    case "ollama":
      return undefined;
    case "custom":
      if (!env.AI_BASE_URL && !env.AI_API_KEY) {
        return "Missing AI_BASE_URL and AI_API_KEY for custom AI fixes.";
      }
      if (!env.AI_BASE_URL) {
        return "Missing AI_BASE_URL for custom AI fixes.";
      }
      if (!env.AI_API_KEY) {
        return "Missing AI_API_KEY for custom AI fixes.";
      }
      return undefined;
    default:
      return `Unsupported AI provider "${provider}".`;
  }
}

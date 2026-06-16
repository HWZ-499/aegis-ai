export interface AiServerEnvironmentSettings {
  provider?: string;
  model?: string;
  baseUrl?: string;
  envFile?: string;
}

export function getAiServerEnvironment(
  settings: AiServerEnvironmentSettings,
  env: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  const provider = (settings.provider || "ollama").toLowerCase().trim();
  const model = settings.model?.trim();
  const baseUrl = settings.baseUrl?.trim();
  const nextEnv: NodeJS.ProcessEnv = {
    ...env,
    AI_PROVIDER: provider,
  };

  if (settings.envFile?.trim() && !nextEnv.AEGIS_ENV_FILE) {
    nextEnv.AEGIS_ENV_FILE = settings.envFile.trim();
  }

  if (model) {
    nextEnv.AI_MODEL = model;
    switch (provider) {
      case "deepseek":
        nextEnv.DEEPSEEK_MODEL = model;
        break;
      case "openai":
        nextEnv.OPENAI_MODEL = model;
        break;
      case "ollama":
        nextEnv.OLLAMA_MODEL = model;
        break;
      default:
        break;
    }
  }

  if (baseUrl) {
    switch (provider) {
      case "deepseek":
        nextEnv.DEEPSEEK_BASE_URL = baseUrl;
        break;
      case "openai":
        nextEnv.OPENAI_BASE_URL = baseUrl;
        break;
      case "ollama":
        nextEnv.OLLAMA_BASE_URL = baseUrl;
        break;
      case "custom":
        nextEnv.AI_BASE_URL = baseUrl;
        break;
      default:
        nextEnv.AI_BASE_URL = baseUrl;
        break;
    }
  }

  return nextEnv;
}

export function getAiConfigurationError(
  provider: string,
  env: NodeJS.ProcessEnv,
  aiEnabled: boolean,
): string | undefined {
  if (!aiEnabled) {
    return "Aegis AI fixes are disabled in settings (aegisAI.ai.enabled = false).";
  }

  switch ((provider || "ollama").toLowerCase()) {
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

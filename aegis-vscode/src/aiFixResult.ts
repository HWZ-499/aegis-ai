export interface GenerateFixSuccess {
  uri: string;
  rule_id: string;
  fixed_code: string;
  confidence: number;
  fix_suggestion: string;
  start_line: number;
  end_line: number;
  requires_review: boolean;
  error_code?: undefined;
  error_message?: undefined;
}

export interface GenerateFixError {
  uri?: string;
  rule_id?: string;
  fixed_code?: string;
  confidence?: number;
  fix_suggestion?: string;
  start_line?: number;
  end_line?: number;
  requires_review?: boolean;
  error_code: string;
  error_message: string;
}

export type GenerateFixResponse = GenerateFixSuccess | GenerateFixError | null;

export interface GenerateFixFailure {
  level: "info" | "warning" | "error";
  message: string;
  actions: GenerateFixFailureAction[];
}

export type GenerateFixFailureAction = "Retry" | "Open AI Settings" | "View Logs";

export function isGenerateFixSuccess(result: GenerateFixResponse): result is GenerateFixSuccess {
  return Boolean(result && !("error_code" in result) && result.fixed_code);
}

export function getGenerateFixFailure(result: GenerateFixResponse): GenerateFixFailure | undefined {
  if (!result) {
    return {
      level: "info",
      message: "Aegis: AI reviewed this finding but did not return a safe replacement.",
      actions: [],
    };
  }

  if ("error_code" in result && result.error_code) {
    switch (result.error_code) {
      case "provider_not_configured":
        return {
          level: "warning",
          message: `Aegis: ${result.error_message}`,
          actions: ["Open AI Settings", "View Logs"],
        };
      case "provider_unavailable":
      case "request_failed":
        return {
          level: "error",
          message: `Aegis: ${result.error_message}`,
          actions: ["Retry", "View Logs"],
        };
      case "no_applicable_fix":
        return { level: "info", message: `Aegis: ${result.error_message}`, actions: [] };
      default:
        return {
          level: "error",
          message: `Aegis: ${result.error_message}`,
          actions: ["Retry", "View Logs"],
        };
    }
  }

  if (!result.fixed_code) {
    return {
      level: "info",
      message: "Aegis: AI reviewed this finding but did not return a safe replacement.",
      actions: [],
    };
  }

  return undefined;
}

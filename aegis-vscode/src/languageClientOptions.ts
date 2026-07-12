import { OutputChannel } from "vscode";
import { LanguageClientOptions, RevealOutputChannelOn } from "vscode-languageclient/node";

export interface AegisInitializationOptions {
  severity_minimum: string;
  exclude_patterns: string[];
  disabled_rules: string[];
  ai_enabled: boolean;
  ai_provider: string;
  scan_on_save: boolean;
  scan_on_change: boolean;
  experimental_cross_file: boolean;
}

export const AEGIS_LANGUAGE_IDS = [
  "javascript",
  "typescript",
  "javascriptreact",
  "typescriptreact",
  "python",
  "php",
  "java",
  "go",
  "c",
  "cpp",
] as const;

/**
 * Build client options without a recursive workspace file watcher.
 * Open/change/save synchronization comes from the document selector; the server
 * does not consume workspace/didChangeWatchedFiles notifications.
 */
export function createLanguageClientOptions(
  outputChannel: OutputChannel,
  initializationOptions: AegisInitializationOptions,
): LanguageClientOptions {
  return {
    documentSelector: AEGIS_LANGUAGE_IDS.map((language) => ({ scheme: "file", language })),
    outputChannel,
    revealOutputChannelOn: RevealOutputChannelOn.Error,
    initializationOptions,
  };
}

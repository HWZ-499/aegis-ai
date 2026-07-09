/**
 * Per-document scan failure state for the extension UI.
 *
 * The LSP clears diagnostics when a scan fails so stale findings do not remain
 * visible. Keep the failure separate from diagnostics; otherwise the normal
 * diagnostics refresh would incorrectly render the failed file as safe.
 */

export interface ScanFailure {
  uri?: string;
  message?: string;
}

const DEFAULT_SCAN_FAILURE_MESSAGE = "The scanner failed before producing diagnostics.";

export function normalizeScanFailureMessage(message?: string): string {
  const normalized = message?.replace(/\s+/g, " ").trim();
  return normalized || DEFAULT_SCAN_FAILURE_MESSAGE;
}

export function scanFailureViewMessage(message?: string): string {
  return `Last scan failed: ${normalizeScanFailureMessage(message)} Open the Aegis output for details.`;
}

export class ScanFailureState {
  private readonly failuresByUri = new Map<string, string>();
  private genericFailure: string | undefined;

  record(failure: ScanFailure): string {
    const message = normalizeScanFailureMessage(failure.message);
    if (failure.uri) {
      this.failuresByUri.set(failure.uri, message);
    } else {
      this.genericFailure = message;
    }
    return message;
  }

  clearForScan(uri?: string): void {
    this.genericFailure = undefined;
    if (uri) {
      this.failuresByUri.delete(uri);
    }
  }

  getForUri(uri?: string): string | undefined {
    if (uri) {
      return this.failuresByUri.get(uri) ?? this.genericFailure;
    }
    return this.genericFailure;
  }
}

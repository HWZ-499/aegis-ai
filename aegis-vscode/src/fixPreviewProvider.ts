/**
 * @fileoverview O2: AI Fix Diff Preview — TextDocumentContentProvider
 *
 * Provides a virtual document with the AI-fixed version of a file,
 * enabling side-by-side diff preview before applying changes.
 *
 * URI scheme: aegis-fix://<encoded-original-uri>?fixId=<id>
 */

import { TextDocumentContentProvider, Uri, EventEmitter, Event } from "vscode";

/** Stored fix data for rendering */
export interface FixPreviewData {
  /** The full source of the fixed file */
  fixedSource: string;
}

/**
 * Content provider for `aegis-fix:` virtual documents.
 * Stores fixed file content keyed by original URI and renders it
 * in VS Code's diff editor.
 */
export class FixPreviewProvider implements TextDocumentContentProvider {
  private _onDidChange = new EventEmitter<Uri>();
  readonly onDidChange: Event<Uri> = this._onDidChange.event;

  /** fixId → fixed source content */
  private _fixes = new Map<string, FixPreviewData>();

  /**
   * Store a fix preview for later retrieval by provideTextDocumentContent.
   *
   * @param fixId Unique key for this fix (e.g. `uri#ruleId#line`)
   * @param data The fixed source content
   * @returns The aegis-fix URI that can be opened in diff editor
   */
  setFix(fixId: string, data: FixPreviewData): Uri {
    this._fixes.set(fixId, data);
    const previewUri = Uri.parse(`aegis-fix://preview/${encodeURIComponent(fixId)}`);
    this._onDidChange.fire(previewUri);
    return previewUri;
  }

  /**
   * Remove a stored fix preview.
   */
  removeFix(fixId: string): void {
    this._fixes.delete(fixId);
  }

  provideTextDocumentContent(uri: Uri): string {
    const fixId = decodeURIComponent(uri.path.replace(/^\//, ""));
    const data = this._fixes.get(fixId);
    return data?.fixedSource ?? "";
  }
}

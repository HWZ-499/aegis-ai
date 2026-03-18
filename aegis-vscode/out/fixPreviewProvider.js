"use strict";
/**
 * @fileoverview O2: AI Fix Diff Preview — TextDocumentContentProvider
 *
 * Provides a virtual document with the AI-fixed version of a file,
 * enabling side-by-side diff preview before applying changes.
 *
 * URI scheme: aegis-fix://<encoded-original-uri>?fixId=<id>
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.FixPreviewProvider = void 0;
const vscode_1 = require("vscode");
/**
 * Content provider for `aegis-fix:` virtual documents.
 * Stores fixed file content keyed by original URI and renders it
 * in VS Code's diff editor.
 */
class FixPreviewProvider {
    constructor() {
        this._onDidChange = new vscode_1.EventEmitter();
        this.onDidChange = this._onDidChange.event;
        /** fixId → fixed source content */
        this._fixes = new Map();
    }
    /**
     * Store a fix preview for later retrieval by provideTextDocumentContent.
     *
     * @param fixId Unique key for this fix (e.g. `uri#ruleId#line`)
     * @param data The fixed source content
     * @returns The aegis-fix URI that can be opened in diff editor
     */
    setFix(fixId, data) {
        this._fixes.set(fixId, data);
        const previewUri = vscode_1.Uri.parse(`aegis-fix://preview/${encodeURIComponent(fixId)}`);
        this._onDidChange.fire(previewUri);
        return previewUri;
    }
    /**
     * Remove a stored fix preview.
     */
    removeFix(fixId) {
        this._fixes.delete(fixId);
    }
    provideTextDocumentContent(uri) {
        const fixId = decodeURIComponent(uri.path.replace(/^\//, ""));
        const data = this._fixes.get(fixId);
        return data?.fixedSource ?? "";
    }
}
exports.FixPreviewProvider = FixPreviewProvider;
//# sourceMappingURL=fixPreviewProvider.js.map
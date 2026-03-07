"use strict";
/**
 * @fileoverview Extension integration tests: activation and command registration.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const assert = __importStar(require("assert"));
const vscode = __importStar(require("vscode"));
const EXT_ID = "aegis-ai.aegis-ai-security";
suite("Extension Test Suite", () => {
    test("Extension should be present in the extension host", () => {
        const ext = vscode.extensions.getExtension(EXT_ID);
        assert.strictEqual(ext !== undefined, true, "Extension aegis-ai.aegis-ai-security should be loaded");
    });
    test("Extension should activate and register commands", async () => {
        const ext = vscode.extensions.getExtension(EXT_ID);
        assert.ok(ext, "Extension must be loaded");
        await ext.activate();
        const commands = await vscode.commands.getCommands();
        assert.ok(commands.includes("aegisAI.showOutput"), "aegisAI.showOutput should be registered");
        assert.ok(commands.includes("aegisAI.scanCurrentFile"), "aegisAI.scanCurrentFile should be registered");
        assert.ok(commands.includes("aegisAI.scanWorkspace"), "aegisAI.scanWorkspace should be registered");
    });
});
//# sourceMappingURL=extension.test.js.map
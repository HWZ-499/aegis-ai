"use strict";
/**
 * @fileoverview Mocha test runner for extension tests.
 * Discovers and runs all *.test.js under the test directory.
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.run = run;
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const mocha_1 = __importDefault(require("mocha"));
function run() {
    const mocha = new mocha_1.default({
        ui: "tdd",
        color: true,
        timeout: 20000,
    });
    const testsRoot = path.resolve(__dirname, "..");
    return new Promise((resolve, reject) => {
        const testFiles = findTestFiles(testsRoot, testsRoot, ".test.js");
        testFiles.forEach((f) => mocha.addFile(path.resolve(testsRoot, f)));
        try {
            mocha.run((failures) => {
                if (failures > 0) {
                    reject(new Error(`${failures} tests failed.`));
                }
                else {
                    resolve();
                }
            });
        }
        catch (err) {
            reject(err);
        }
    });
}
/**
 * Recursively find all files matching suffix under dir.
 * @param dir - Current directory to search
 * @param root - Root directory (for relative paths)
 * @param suffix - File suffix (e.g. .test.js)
 * @returns Relative paths from root
 */
function findTestFiles(dir, root, suffix) {
    const results = [];
    if (!fs.existsSync(dir))
        return results;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const e of entries) {
        const full = path.join(dir, e.name);
        const rel = path.relative(root, full);
        if (e.isDirectory()) {
            results.push(...findTestFiles(full, root, suffix));
        }
        else if (e.isFile() && e.name.endsWith(suffix)) {
            results.push(rel);
        }
    }
    return results;
}
//# sourceMappingURL=index.js.map
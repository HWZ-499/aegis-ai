import { execFile } from "child_process";

export interface PythonVersion {
  major: number;
  minor: number;
  patch: number;
  raw: string;
}

export type ExecFileCallback = (error: Error | null, stdout: string, stderr: string) => void;

export type ExecFileLike = (
  file: string,
  args: readonly string[],
  options: {
    encoding: BufferEncoding;
    timeout: number;
  },
  callback: ExecFileCallback,
) => void;

function execFileAdapter(
  file: string,
  args: readonly string[],
  options: { encoding: BufferEncoding; timeout: number },
  callback: ExecFileCallback,
): void {
  execFile(file, args, options, (error, stdout, stderr) => {
    callback(error, stdout ?? "", stderr ?? "");
  });
}

export function probePythonVersion(
  pythonPath: string,
  runExecFile: ExecFileLike = execFileAdapter,
): Promise<string> {
  return new Promise((resolve, reject) => {
    runExecFile(
      pythonPath,
      ["--version"],
      { encoding: "utf8", timeout: 5000 },
      (error, stdout, stderr) => {
        if (error) {
          reject(error);
          return;
        }
        resolve((stdout || stderr).trim());
      },
    );
  });
}

export function parsePythonVersion(output: string): PythonVersion | undefined {
  const raw = output.trim();
  const match = raw.match(/Python\s+(\d+)\.(\d+)(?:\.(\d+))?/i);
  if (!match) {
    return undefined;
  }

  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3] ?? "0"),
    raw,
  };
}

export function isPythonVersionSupported(
  output: string,
  minMajor = 3,
  minMinor = 10,
  maxMajor = 3,
  maxMinor = 12,
): boolean {
  const version = parsePythonVersion(output);
  if (!version) {
    return false;
  }
  const versionKey = version.major * 100 + version.minor;
  const minimumKey = minMajor * 100 + minMinor;
  const maximumKey = maxMajor * 100 + maxMinor;
  return versionKey >= minimumKey && versionKey <= maximumKey;
}

import { execFile } from "child_process";

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

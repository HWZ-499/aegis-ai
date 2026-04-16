export interface AegisCommentBlock {
  startLine: number;
  endLineExclusive: number;
}

const AEGIS_COMMENT_MARKERS = ["Aegis 修复建议", "Aegis AI 修复建议"];

function isCommentLine(line: string): boolean {
  const trimmed = line.trim();
  return trimmed.startsWith("#") || trimmed.startsWith("//");
}

function isAegisGeneratedComment(line: string): boolean {
  return AEGIS_COMMENT_MARKERS.some((marker) => line.includes(marker));
}

export function findAegisCommentBlock(source: string, zeroBasedLine: number): AegisCommentBlock | null {
  const lines = source.split(/\r?\n/);
  if (zeroBasedLine < 0 || zeroBasedLine >= lines.length) {
    return null;
  }
  if (!isCommentLine(lines[zeroBasedLine])) {
    return null;
  }

  let startLine: number | null = null;
  for (let line = zeroBasedLine; line >= 0 && isCommentLine(lines[line]); line -= 1) {
    if (isAegisGeneratedComment(lines[line])) {
      startLine = line;
      break;
    }
  }

  if (startLine === null) {
    return null;
  }

  let endLineExclusive = startLine + 1;
  while (endLineExclusive < lines.length && isCommentLine(lines[endLineExclusive])) {
    endLineExclusive += 1;
  }

  return { startLine, endLineExclusive };
}

export function removeAegisCommentBlock(source: string, zeroBasedLine: number): string {
  const block = findAegisCommentBlock(source, zeroBasedLine);
  if (!block) {
    return source;
  }

  const lineBreak = source.includes("\r\n") ? "\r\n" : "\n";
  const lines = source.split(/\r?\n/);
  const updated = [
    ...lines.slice(0, block.startLine),
    ...lines.slice(block.endLineExclusive),
  ];
  return updated.join(lineBreak);
}

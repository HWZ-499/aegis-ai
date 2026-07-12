export interface WorkspaceScanProgressReporter {
  report(value: { message?: string; increment?: number }): void;
}

export interface WorkspaceScanProgressNotification {
  scanId?: string;
  current?: number;
  total?: number;
  uri?: string;
}

interface ActiveWorkspaceScan {
  scanId: string;
  reporter: WorkspaceScanProgressReporter;
  resolve: () => void;
  completedFraction: number;
}

/** Tracks one user-triggered workspace scan and rejects stale progress notifications. */
export class WorkspaceScanProgress {
  private active: ActiveWorkspaceScan | undefined;

  get isActive(): boolean {
    return this.active !== undefined;
  }

  start(scanId: string, reporter: WorkspaceScanProgressReporter): Promise<void> {
    if (this.active) {
      throw new Error("A workspace scan is already in progress.");
    }
    return new Promise<void>((resolve) => {
      this.active = { scanId, reporter, resolve, completedFraction: 0 };
    });
  }

  report(notification: WorkspaceScanProgressNotification): void {
    const active = this.active;
    if (!active || (notification.scanId && notification.scanId !== active.scanId)) {
      return;
    }

    const total = normalizeCount(notification.total);
    const current = Math.min(normalizeCount(notification.current), total);
    if (total === 0) {
      active.reporter.report({ message: "No supported files found" });
      this.finish(active.scanId);
      return;
    }

    const completedFraction = current / total;
    const increment = Math.max(0, completedFraction - active.completedFraction) * 100;
    active.completedFraction = Math.max(active.completedFraction, completedFraction);
    active.reporter.report({
      message: `Scanning ${current}/${total}`,
      increment,
    });
    if (current >= total) {
      this.finish(active.scanId);
    }
  }

  finish(scanId: string): void {
    if (!this.active || this.active.scanId !== scanId) {
      return;
    }
    const { resolve } = this.active;
    this.active = undefined;
    resolve();
  }
}

function normalizeCount(value: number | undefined): number {
  return typeof value === "number" && Number.isFinite(value)
    ? Math.max(0, Math.floor(value))
    : 0;
}

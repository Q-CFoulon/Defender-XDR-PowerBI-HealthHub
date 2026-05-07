import { mkdir, readFile, writeFile } from "fs/promises";
import path from "path";
import { logger } from "../config/logger";
import type { UnifiedSnapshot } from "../types/domain";

export class SnapshotStoreService {
  private readonly snapshotPath: string;

  public constructor(private readonly dataDirectory: string) {
    this.snapshotPath = path.join(this.dataDirectory, "latest-snapshot.json");
  }

  public async save(snapshot: UnifiedSnapshot): Promise<void> {
    await mkdir(this.dataDirectory, { recursive: true });
    await writeFile(this.snapshotPath, JSON.stringify(snapshot, null, 2), "utf-8");
  }

  public async loadLatest(): Promise<UnifiedSnapshot | null> {
    try {
      const fileContent = await readFile(this.snapshotPath, "utf-8");
      return JSON.parse(fileContent) as UnifiedSnapshot;
    } catch (error) {
      logger.debug({ error }, "No previous snapshot found in local data store");
      return null;
    }
  }
}

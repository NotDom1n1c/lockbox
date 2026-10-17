// JSON file store: atomic writes (temp file + rename), readable only by the owner.
import { readFile, writeFile, rename, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

export class FileStore {
  constructor(path) { this.path = path; }

  async load() {
    try {
      return JSON.parse(await readFile(this.path, "utf8"));
    } catch (err) {
      if (err.code === "ENOENT") return null;
      throw err;
    }
  }

  async save(state) {
    await mkdir(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.${process.pid}.tmp`;
    await writeFile(tmp, JSON.stringify(state), { mode: 0o600 });
    await rename(tmp, this.path);
  }
}

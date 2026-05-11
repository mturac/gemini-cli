/**
 * @license
 * Copyright 2026 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fileExists } from '../utils/fileUtils.js';
import { resolveExecutable } from '../utils/shell-utils.js';
import { isSubpath, resolveToRealPath } from '../utils/paths.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Service for locating and managing the ripgrep executable.
 */
export class RipgrepService {
  private cachedRgPath: string | null | undefined = undefined;

  constructor(private readonly projectRoot: string) {}

  /**
   * Resets the cached ripgrep path.
   */
  resetCache(): void {
    this.cachedRgPath = undefined;
  }

  /**
   * Returns the path to the ripgrep binary, or null if not found or unsafe.
   */
  async getRipgrepPath(): Promise<string | null> {
    if (this.cachedRgPath !== undefined) {
      return this.cachedRgPath;
    }

    const platform = os.platform();
    const arch = os.arch();

    // Map to the correct bundled binary
    const binName = `rg-${platform}-${arch}${platform === 'win32' ? '.exe' : ''}`;

    const candidatePaths = [
      // 1. SEA runtime layout: everything is flattened into the root dir
      path.resolve(__dirname, 'vendor/ripgrep', binName),
      // 2. Dev/Dist layout: packages/core/dist/tools/ripGrep.js -> packages/core/vendor/ripgrep
      path.resolve(__dirname, '../../vendor/ripgrep', binName),
    ];

    for (const candidate of candidatePaths) {
      if (await fileExists(candidate)) {
        this.cachedRgPath = candidate;
        return candidate;
      }
    }

    // 3. Fallback: check system PATH
    const systemRg = await resolveExecutable('rg');
    if (systemRg) {
      // Security: Validate the system executable to prevent Search Path Interruption.
      // We resolve to real path and ensure it's not in the project root or CWD.
      const realPath = resolveToRealPath(systemRg);

      if (this.isTrustedSystemPath(realPath)) {
        // Return command name 'rg' to remain compatible with sandbox allowlists
        this.cachedRgPath = 'rg';
        return 'rg';
      }
    }

    this.cachedRgPath = null;
    return null;
  }

  /**
   * Checks if ripgrep is available.
   */
  async canUseRipgrep(): Promise<boolean> {
    return (await this.getRipgrepPath()) !== null;
  }

  /**
   * Verifies if a path is a trusted system directory.
   */
  private isTrustedSystemPath(filePath: string): boolean {
    // 1. Never allow paths within the project root or current working directory
    // (unless they are our bundled ones, which are handled above)
    if (isSubpath(this.projectRoot, filePath)) {
      return false;
    }

    const cwd = process.cwd();
    if (isSubpath(cwd, filePath)) {
      return false;
    }

    // 2. Allow standard system directories
    const platform = os.platform();
    if (platform === 'win32') {
      const trustedPrefixes = [
        process.env['SystemRoot'] || 'C:\\Windows',
        process.env['ProgramFiles'] || 'C:\\Program Files',
        process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)',
      ].map((p) => p.toLowerCase());

      const lowerPath = filePath.toLowerCase();
      return trustedPrefixes.some((prefix) => lowerPath.startsWith(prefix));
    } else {
      const trustedPrefixes = [
        '/usr/bin',
        '/bin',
        '/usr/local/bin',
        '/opt/homebrew/bin',
        '/usr/sbin',
        '/sbin',
      ];

      return trustedPrefixes.some((prefix) => filePath.startsWith(prefix));
    }
  }
}

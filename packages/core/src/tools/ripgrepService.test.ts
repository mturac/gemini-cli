/**
 * @license
 * Copyright 2026 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { RipgrepService } from './ripgrepService.js';
import { fileExists } from '../utils/fileUtils.js';
import { resolveExecutable } from '../utils/shell-utils.js';
import { resolveToRealPath } from '../utils/paths.js';
import path from 'node:path';
import os from 'node:os';

vi.mock('../utils/fileUtils.js', () => ({
  fileExists: vi.fn(),
}));

vi.mock('../utils/shell-utils.js', () => ({
  resolveExecutable: vi.fn(),
}));

vi.mock('../utils/paths.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../utils/paths.js')>();
  return {
    ...actual,
    resolveToRealPath: vi.fn((p) => p),
    isSubpath: vi.fn((parent, child) => child.startsWith(parent)),
  };
});

describe('RipgrepService', () => {
  let service: RipgrepService;
  const projectRoot = path.resolve('/project');

  beforeEach(() => {
    vi.resetAllMocks();
    service = new RipgrepService(projectRoot);
  });

  describe('getRipgrepPath', () => {
    it('should resolve bundled path if it exists', async () => {
      vi.mocked(fileExists).mockResolvedValue(true);

      const resolvedPath = await service.getRipgrepPath();
      expect(resolvedPath).toContain('vendor/ripgrep');
      expect(vi.mocked(fileExists)).toHaveBeenCalled();
    });

    it('should fall back to system PATH if bundled is missing and system is trusted', async () => {
      vi.mocked(fileExists).mockResolvedValue(false);
      const systemPath =
        os.platform() === 'win32'
          ? 'C:\\Windows\\System32\\rg.exe'
          : '/usr/bin/rg';
      vi.mocked(resolveExecutable).mockResolvedValue(systemPath);
      vi.mocked(resolveToRealPath).mockReturnValue(systemPath);

      const resolvedPath = await service.getRipgrepPath();
      expect(resolvedPath).toBe('rg');
      expect(resolveExecutable).toHaveBeenCalledWith('rg');
    });

    it('should reject system PATH if it is in the project root (unsafe)', async () => {
      vi.mocked(fileExists).mockResolvedValue(false);
      const unsafePath = path.join(projectRoot, 'malicious-rg');
      vi.mocked(resolveExecutable).mockResolvedValue(unsafePath);
      vi.mocked(resolveToRealPath).mockReturnValue(unsafePath);

      const resolvedPath = await service.getRipgrepPath();
      expect(resolvedPath).toBeNull();
    });

    it('should reject system PATH if it is in the CWD (unsafe)', async () => {
      vi.mocked(fileExists).mockResolvedValue(false);
      const cwd = process.cwd();
      const unsafePath = path.join(cwd, 'malicious-rg');
      vi.mocked(resolveExecutable).mockResolvedValue(unsafePath);
      vi.mocked(resolveToRealPath).mockReturnValue(unsafePath);

      const resolvedPath = await service.getRipgrepPath();
      expect(resolvedPath).toBeNull();
    });

    it('should return null if not found anywhere', async () => {
      vi.mocked(fileExists).mockResolvedValue(false);
      vi.mocked(resolveExecutable).mockResolvedValue(undefined);

      const resolvedPath = await service.getRipgrepPath();
      expect(resolvedPath).toBeNull();
    });

    it('should cache the result', async () => {
      vi.mocked(fileExists).mockResolvedValue(true);

      await service.getRipgrepPath();
      await service.getRipgrepPath();

      expect(vi.mocked(fileExists)).toHaveBeenCalledTimes(1);
    });
  });

  describe('OS/Architecture Resolution', () => {
    it.each([
      { platform: 'darwin', arch: 'arm64', expectedBin: 'rg-darwin-arm64' },
      { platform: 'darwin', arch: 'x64', expectedBin: 'rg-darwin-x64' },
      { platform: 'linux', arch: 'arm64', expectedBin: 'rg-linux-arm64' },
      { platform: 'linux', arch: 'x64', expectedBin: 'rg-linux-x64' },
      { platform: 'win32', arch: 'x64', expectedBin: 'rg-win32-x64.exe' },
    ])(
      'should map $platform $arch to $expectedBin',
      async ({ platform, arch, expectedBin }) => {
        vi.spyOn(os, 'platform').mockReturnValue(platform as NodeJS.Platform);
        vi.spyOn(os, 'arch').mockReturnValue(arch);
        vi.mocked(fileExists).mockImplementation(async (checkPath) =>
          checkPath.endsWith(expectedBin),
        );

        const resolvedPath = await service.getRipgrepPath();
        expect(resolvedPath).not.toBeNull();
        expect(resolvedPath?.endsWith(expectedBin)).toBe(true);
      },
    );
  });

  describe('Path Fallback Logic', () => {
    beforeEach(() => {
      vi.spyOn(os, 'platform').mockReturnValue('linux');
      vi.spyOn(os, 'arch').mockReturnValue('x64');
    });

    it('should resolve the SEA (flattened) path first', async () => {
      vi.mocked(fileExists).mockImplementation(async (checkPath) =>
        checkPath.includes(path.normalize('tools/vendor/ripgrep')),
      );

      const resolvedPath = await service.getRipgrepPath();
      expect(resolvedPath).not.toBeNull();
      expect(resolvedPath).toContain(path.normalize('tools/vendor/ripgrep'));
    });

    it('should fall back to the Dev path if SEA path is missing', async () => {
      vi.mocked(fileExists).mockImplementation(
        async (checkPath) =>
          checkPath.includes(path.normalize('core/vendor/ripgrep')) &&
          !checkPath.includes(path.join(path.sep, 'tools', path.sep)),
      );

      const resolvedPath = await service.getRipgrepPath();
      expect(resolvedPath).not.toBeNull();
      expect(resolvedPath).toContain(path.normalize('core/vendor/ripgrep'));
      expect(resolvedPath).not.toContain(
        path.join(path.sep, 'tools', path.sep),
      );
    });
  });
});

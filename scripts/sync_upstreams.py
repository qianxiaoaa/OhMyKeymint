#!/usr/bin/env python3
"""Sync OhMyKeymint and yypm php-server into this fork, then reapply OMK edits."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STATE_PATH = REPO_ROOT / "scripts" / "upstream-sync.json"
DEFAULT_AUTHOR_NAME = "qianxiaoaa"
DEFAULT_AUTHOR_EMAIL = "qianxiaoaa@users.noreply.github.com"
OMK_VERSION_CODE_FALLBACK = 1
YYPM_SKIP_NAMES = {".gitignore"}
YYPM_SKIP_RELATIVE = {"README.md"}


class SyncError(RuntimeError):
    pass


def run(cmd, *, cwd=None, env=None, check=True, capture=False):
    print("+", " ".join(cmd))
    result = subprocess.run(
        cmd,
        cwd=cwd or REPO_ROOT,
        env=env,
        text=True,
        capture_output=capture,
    )
    if check and result.returncode != 0:
        detail = ""
        if capture:
            detail = (result.stderr or result.stdout or "").strip()
            if detail:
                detail = ": " + detail
        raise SyncError("command failed: " + " ".join(cmd) + detail)
    return result


def git_output(cmd, *, cwd=None):
    return (run(cmd, cwd=cwd, capture=True).stdout or "").strip()


def load_state():
    if not STATE_PATH.is_file():
        raise SyncError("missing upstream state file: " + str(STATE_PATH))
    return json.loads(STATE_PATH.read_text(encoding="utf-8"))


def write_state(state):
    STATE_PATH.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def cargo_version():
    for line in (REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"')
    return "1.3.6"


def ensure_author_env():
    env = os.environ.copy()
    env.setdefault("GIT_AUTHOR_NAME", DEFAULT_AUTHOR_NAME)
    env.setdefault("GIT_AUTHOR_EMAIL", DEFAULT_AUTHOR_EMAIL)
    env.setdefault("GIT_COMMITTER_NAME", env["GIT_AUTHOR_NAME"])
    env.setdefault("GIT_COMMITTER_EMAIL", env["GIT_AUTHOR_EMAIL"])
    return env


def commit_if_needed(message, env, paths=None):
    add_paths = paths or ["server", "scripts/upstream-sync.json"]
    run(["git", "add", "--"] + add_paths, env=env)
    if not git_output(["git", "diff", "--cached", "--name-only", "--"] + add_paths):
        return False
    run(
        [
            "git",
            "commit",
            "--no-verify",
            "--no-gpg-sign",
            "--only",
            "-m",
            message,
            "--",
        ]
        + add_paths,
        env=env,
    )
    return True


def replace_first_block(text, start, end, replacement):
    start_idx = text.find(start)
    end_idx = text.find(end)
    if start_idx < 0 or end_idx < 0 or end_idx < start_idx:
        raise SyncError("failed to locate block starting with " + repr(start))
    return replacement + text[end_idx:]


def omk_config_header():
    return """<?php
/**
 * 全局配置 —— 部署在网站目录 /api/omk/ 下，自包含。
 * update.php（cron/web 调用）与 index.php（web）都会加载本文件。
 *
 * 这是 OhMyKeymint（OMK）适配版：服务端把 keybox 与模块包下发给 OMK 客户端
 * 的 [remote_keybox] 特性。源码基于 yypm 的 PHP 服务端。
 *
 * 说明：
 *   - 所有数据（keybox.xml / manifest.json / module.zip）与密钥都在本目录内。
 *   - 私钥 keys/ed25519.key 由 www 用户持有（600），并通过 nginx 规则禁止 web 直接访问。
 *   - 首次运行 update.php 会生成密钥并把公钥写入 keys/ed25519.pub；
 *     把该公钥填入 OMK 客户端 src/remote_keybox.rs 的 TRUSTED_PUBKEY_B64 后重新编译。
 */
"""


def omk_index_header():
    return """<?php
/**
 * API 入口 —— 部署到 /api/omk/index.php。
 * 自包含：只读同目录 data/ 下的 keybox.xml / manifest.json / module.zip，
 * 不依赖 web 根之外的任何文件（兼容 open_basedir）。
 *
"""


def omk_scan_header():
    return """#!/bin/bash
# =========================================================
# OhMyKeymint 附属模块清单扫描 —— 供计划任务 / update.sh 调用
# 扫描 package/ 目录，读出每个 zip 内的 module.prop，
# 生成带版本信息的 package.json（对旧客户端向后兼容）
# =========================================================
"""


def omk_update_sh_header():
    return """#!/bin/bash
# =========================================================
# OhMyKeymint keybox 更新脚本 —— 计划任务(cron)/宝塔计划任务执行此脚本
# 以 www 用户运行 PHP（与网站 PHP 进程同用户）
# =========================================================
"""


def preserve_config_versions(config):
    version = cargo_version()
    out = []
    replaced_version = False
    replaced_code = False
    for line in config.splitlines(keepends=True):
        stripped = line.lstrip()
        prefix = line[: len(line) - len(stripped)]
        if stripped.startswith("'version'"):
            out.append(prefix + "'version'      => '" + version + "',\n")
            replaced_version = True
            continue
        if stripped.startswith("'version_code'"):
            out.append(prefix + "'version_code' => " + str(OMK_VERSION_CODE_FALLBACK) + ",\n")
            replaced_code = True
            continue
        out.append(line)
    if not replaced_version or not replaced_code:
        raise SyncError("failed to rewrite OMK fallback version fields")
    text = "".join(out)
    marker = "兜底版本号：manifest 里的 version/version_code 优先取自 data/module.zip"
    if marker not in text:
        text = text.replace(
            "    'keybox_pin' => __DIR__ . '/data/keybox.pinned.xml',\n\n",
            "    'keybox_pin' => __DIR__ . '/data/keybox.pinned.xml',\n\n"
            "    // 兜底版本号：manifest 里的 version/version_code 优先取自 data/module.zip 内的\n"
            "    // module.prop。只有当包缺失或解析不到时才回退到这里。\n",
            1,
        )
    return text


def apply_omk_php_adaptations():
    config_path = REPO_ROOT / "server" / "config.php"
    config = replace_first_block(
        config_path.read_text(encoding="utf-8"),
        "<?php",
        "return [",
        omk_config_header(),
    )
    config = config.replace("/api/kernelsu/module", "/api/omk")
    if "这是 OhMyKeymint（OMK）适配版" not in config:
        raise SyncError("OMK config header was not applied")
    config_path.write_text(preserve_config_versions(config), encoding="utf-8")

    index_path = REPO_ROOT / "server" / "public" / "index.php"
    index = replace_first_block(
        index_path.read_text(encoding="utf-8"),
        "<?php",
        " * 路由（query 参数 action）：",
        omk_index_header(),
    )
    index_path.write_text(index.replace("/api/kernelsu/module", "/api/omk"), encoding="utf-8")

    scan_path = REPO_ROOT / "server" / "scan_packages.sh"
    scan_path.write_text(
        replace_first_block(
            scan_path.read_text(encoding="utf-8"),
            "#!/bin/bash",
            "set -u",
            omk_scan_header(),
        ),
        encoding="utf-8",
    )

    update_sh_path = REPO_ROOT / "server" / "update.sh"
    update_sh = replace_first_block(
        update_sh_path.read_text(encoding="utf-8"),
        "#!/bin/bash",
        "PHP=",
        omk_update_sh_header(),
    )
    update_sh_path.write_text(update_sh.replace("/api/kernelsu/module", "/api/omk"), encoding="utf-8")


def copy_yypm_php_server(yypm_dir):
    src = yypm_dir / "php-server"
    dst = REPO_ROOT / "server"
    if not src.is_dir():
        raise SyncError("yypm php-server is missing at " + str(src))
    dst.mkdir(parents=True, exist_ok=True)
    src_files = {
        path.relative_to(src).as_posix() for path in src.rglob("*") if path.is_file()
    }
    for path in list(dst.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(dst)
        if relative.name in YYPM_SKIP_NAMES or relative.as_posix() in YYPM_SKIP_RELATIVE:
            continue
        if relative.as_posix() not in src_files:
            path.unlink()
    for path in src.rglob("*"):
        relative = path.relative_to(src)
        if relative.name in YYPM_SKIP_NAMES or relative.as_posix() in YYPM_SKIP_RELATIVE:
            continue
        target = dst / relative
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def merge_ohmykeymint(sha, env):
    result = run(
        [
            "git",
            "merge",
            "--no-ff",
            "--no-verify",
            "--no-gpg-sign",
            "--no-edit",
            "-m",
            "Merge ITxiao6666/OhMyKeymint " + sha[:7] + " into this fork [skip ci]",
            sha,
        ],
        env=env,
        check=False,
        capture=True,
    )
    if result.returncode == 0:
        output = (result.stdout or "") + (result.stderr or "")
        return "Already up to date" not in output
    status = git_output(["git", "status", "--porcelain"])
    unmerged = [
        line
        for line in status.splitlines()
        if line.startswith(("UU ", "AA ", "DD ", "AU ", "UA ", "DU ", "UD "))
    ]
    if unmerged:
        run(["git", "merge", "--abort"], env=env, check=False)
        raise SyncError("OhMyKeymint merge has unresolved conflicts:\n" + "\n".join(unmerged))
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    raise SyncError("OhMyKeymint merge failed")


def parser():
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--ohmykeymint-dir", type=Path, default=Path("/tmp/upstream-ohmykeymint"))
    command.add_argument("--yypm-dir", type=Path, default=Path("/tmp/upstream-yypm"))
    command.add_argument("--ohmykeymint-sha")
    command.add_argument("--yypm-sha")
    command.add_argument("--force", action="store_true")
    return command


def main():
    args = parser().parse_args()
    env = ensure_author_env()
    state = load_state()
    ohmykeymint_ref = state.get("ohmykeymint_ref", "master")
    yypm_ref = state.get("yypm_ref", "main")
    ohmykeymint_sha = args.ohmykeymint_sha or git_output(
        ["git", "rev-parse", "origin/" + ohmykeymint_ref],
        cwd=args.ohmykeymint_dir,
    )
    yypm_sha = args.yypm_sha or git_output(
        ["git", "rev-parse", "origin/" + yypm_ref],
        cwd=args.yypm_dir,
    )
    changed = False
    recorded_omk = state.get("ohmykeymint_sha", "")
    recorded_yypm = state.get("yypm_sha", "")

    if ohmykeymint_sha != recorded_omk:
        print("Syncing ITxiao6666/OhMyKeymint " + recorded_omk[:7] + " -> " + ohmykeymint_sha[:7])
        run(["git", "fetch", str(args.ohmykeymint_dir), ohmykeymint_ref], env=env)
        fetched = git_output(["git", "rev-parse", "FETCH_HEAD"])
        if fetched != ohmykeymint_sha:
            raise SyncError("fetched OhMyKeymint SHA " + fetched + " does not match " + ohmykeymint_sha)
        if merge_ohmykeymint(ohmykeymint_sha, env):
            changed = True
    else:
        print("ITxiao6666/OhMyKeymint is already at " + ohmykeymint_sha[:7])

    if yypm_sha != recorded_yypm or args.force:
        print("Syncing yangyang8002/yypm php-server " + recorded_yypm[:7] + " -> " + yypm_sha[:7])
        copy_yypm_php_server(args.yypm_dir)
        apply_omk_php_adaptations()
        if commit_if_needed(
            "Adapt yypm php-server " + yypm_sha[:7] + " for OhMyKeymint [skip ci]",
            env,
            paths=["server"],
        ):
            changed = True
        else:
            print("yypm php-server tree already matches the adapted copy")
    else:
        print("yangyang8002/yypm is already at " + yypm_sha[:7])

    state["ohmykeymint_sha"] = ohmykeymint_sha
    state["ohmykeymint_ref"] = ohmykeymint_ref
    state["yypm_sha"] = yypm_sha
    state["yypm_ref"] = yypm_ref
    write_state(state)
    if commit_if_needed(
        "Record upstream SHAs " + ohmykeymint_sha[:7] + " / " + yypm_sha[:7] + " [skip ci]",
        env,
        paths=["scripts/upstream-sync.json"],
    ):
        changed = True

    head_sha = git_output(["git", "rev-parse", "HEAD"])
    short_sha = head_sha[:7]
    commit_count = git_output(["git", "rev-list", "--count", "HEAD"])
    version = cargo_version()
    for key, value in (
        ("changed", str(changed).lower()),
        ("ohmykeymint_sha", ohmykeymint_sha),
        ("yypm_sha", yypm_sha),
        ("head_sha", head_sha),
        ("version", version),
        ("commit_count", commit_count),
        ("short_sha", short_sha),
        ("tag", "v" + version + "-" + commit_count + "-" + short_sha),
    ):
        print(key + "=" + value, flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SyncError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)


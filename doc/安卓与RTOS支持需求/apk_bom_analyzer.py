#!/usr/bin/env python3
"""Analyze Android APK files and produce a CycloneDX-compatible BOM + CSV.

Extracts package identity, versions, permissions, signing cert, native libs,
and (when classes.dex is stripped) library hints from the paired .odex.
"""
from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
import zipfile
from datetime import datetime, timezone

from pyaxmlparser import APK

# Common third-party Java/Android library package prefixes (dex type descriptors).
LIB_HINTS = {
    "Lcom/google/gson": "gson",
    "Lcom/google/android/gms": "google-play-services",
    "Lcom/google/firebase": "firebase",
    "Lcom/squareup/okhttp3": "okhttp3",
    "Lcom/squareup/okhttp": "okhttp",
    "Lokhttp3": "okhttp",
    "Lcom/android/volley": "android-volley",
    "Lorg/apache/http": "apache-httpclient",
    "Lorg/json": "org.json",
    "Lcom/fasterxml/jackson": "jackson",
    "Lorg/slf4j": "slf4j",
    "Lch/qos/logback": "logback",
    "Lcom/facebook": "facebook-sdk",
    "Lcom/umeng": "umeng-analytics",
    "Lcom/alipay": "alipay-sdk",
    "Lcom/taobao": "taobao-sdk",
    "Lcom/baidu": "baidu-sdk",
    "Lcom/tencent": "tencent-sdk",
    "Lcom/bugly": "bugly-crash",
    "Lcom/adjust": "adjust",
    "Lcom/amplitude": "amplitude",
    "Lio/reactivex": "reactivex",
    "Lrx/": "rxjava",
    "Lretrofit2": "retrofit2",
    "Lcom/orm/": "ormlite-sugar",
    "Lorg/litepal": "litepal",
    "Lcom/j256/ormlite": "ormlite",
    "Lorg/apache/commons": "apache-commons",
    "Lorg/bouncycastle": "bouncycastle",
    "Ljavax/crypto": "javax-crypto",
    "Lcom/caverock": "androidsvg",
    "Lcom/nostra13": "universal-image-loader",
    "Lcom/bumptech/glide": "glide",
    "Lcom/squareup/picasso": "picasso",
    "Lcom/actionbarsherlock": "actionbarsherlock",
    "Landroid/support/": "android-support-lib",
    "Landroidx/": "androidx",
    "Lcom/neldtv": "neldtv-app",
    "Lcom/amlogic": "amlogic-sdk",
    "Ltv/danmaku": "danmaku-bili",
    "Lorg/videolan": "libvlc-android",
    "Lcom/google/protobuf": "protobuf-java",
    "Lnet/sf/scguard": "scguard",
}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_file(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def strings_from(path: str, min_len: int = 6) -> list[str]:
    try:
        out = subprocess.run(
            ["strings", "-n", str(min_len), path],
            capture_output=True, text=True, timeout=60,
        )
        return out.stdout.splitlines()
    except Exception:
        return []


def dex_hints_from_odex(odex_path: str) -> list[str]:
    """Detect known library packages from odex strings."""
    if not os.path.isfile(odex_path):
        return []
    lines = strings_from(odex_path, 4)
    found: set[str] = set()
    # Direct full type descriptors
    text = "\n".join(lines)
    for prefix, name in LIB_HINTS.items():
        if prefix in text:
            found.add(name)
    # Also scan line-by-line for L...; descriptors
    for line in lines:
        for m in re.finditer(r"L[a-zA-Z][\w$]*(?:/[\w$]+)+;", line):
            desc = m.group(0)
            for prefix, name in LIB_HINTS.items():
                if desc.startswith(prefix):
                    found.add(name)
    return sorted(found)


def cert_info(apk: APK) -> dict:
    info = {
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "sha256": None,
        "serial": None,
        "signature_names": [],
    }
    try:
        certs = apk.get_certificates()
    except Exception:
        certs = []
    if not certs:
        # older/odd signature schemes
        try:
            certs = apk.get_signature_names() and []
        except Exception:
            certs = []
    for c in certs or []:
        try:
            info["subject"] = str(c.subject.human_friendly)
            info["issuer"] = str(c.issuer.human_friendly)
            info["not_before"] = c.not_valid_before.isoformat() if hasattr(c, "not_valid_before") else None
            info["not_after"] = c.not_valid_after.isoformat() if hasattr(c, "not_valid_after") else None
            try:
                der = c.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER)
                info["sha256"] = hashlib.sha256(der).hexdigest()
            except Exception:
                pass
            try:
                info["serial"] = str(c.serial_number)
            except Exception:
                pass
            break
        except Exception:
            continue
    try:
        info["signature_names"] = list(apk.get_signature_names() or [])
    except Exception:
        pass
    return info


def analyze_apk(path: str) -> dict:
    rec: dict = {
        "path": path,
        "file_name": os.path.basename(path),
        "size": os.path.getsize(path),
        "sha256": sha256_file(path),
        "md5": md5_file(path),
        "package": None,
        "version_name": None,
        "version_code": None,
        "min_sdk": None,
        "target_sdk": None,
        "permissions": [],
        "permission_count": 0,
        "activities": 0,
        "services": 0,
        "receivers": 0,
        "providers": 0,
        "has_dex": False,
        "dex_entries": [],
        "native_libs": [],
        "native_lib_count": 0,
        "odex_path": None,
        "odex_sha256": None,
        "lib_hints": [],
        "cert": {},
        "zip_entries": 0,
        "error": None,
    }
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            rec["zip_entries"] = len(names)
            rec["dex_entries"] = [n for n in names if n.endswith(".dex")]
            rec["has_dex"] = bool(rec["dex_entries"])
            rec["native_libs"] = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
            rec["native_lib_count"] = len(rec["native_libs"])
    except Exception as e:
        rec["error"] = f"zip: {e}"

    # Paired odex (same dir, same stem)
    stem = os.path.splitext(path)[0]
    odex = stem + ".odex"
    if os.path.isfile(odex):
        rec["odex_path"] = odex
        try:
            rec["odex_sha256"] = sha256_file(odex)
            rec["lib_hints"] = dex_hints_from_odex(odex)
        except Exception:
            pass

    try:
        apk = APK(path)
        rec["package"] = apk.package
        rec["version_name"] = getattr(apk, "version_name", None) or (
            apk.get_attribute_value("manifest", "versionName") if hasattr(apk, "get_attribute_value") else None
        )
        # pyaxmlparser attributes
        for attr, key in [
            ("version_name", "version_name"),
            ("version_code", "version_code"),
        ]:
            v = getattr(apk, attr, None)
            if v is not None:
                rec[key] = v
        # get_* fallbacks
        try:
            rec["version_name"] = rec["version_name"] or apk.get_androidmanifest_xml().get(
                "{http://schemas.android.com/apk/res/android}versionName"
            )
        except Exception:
            pass
        try:
            rc = apk.get_androidmanifest_xml().get("{http://schemas.android.com/apk/res/android}versionCode")
            if rec["version_code"] is None and rc is not None:
                rec["version_code"] = int(rc)
        except Exception:
            pass
        try:
            rec["min_sdk"] = apk.get_min_sdk_version()
            rec["target_sdk"] = apk.get_target_sdk_version()
        except Exception:
            pass
        try:
            perms = list(apk.get_permissions() or [])
            rec["permissions"] = perms
            rec["permission_count"] = len(perms)
        except Exception:
            pass
        try:
            rec["activities"] = len(apk.get_activities() or [])
            rec["services"] = len(apk.get_services() or [])
            rec["receivers"] = len(apk.get_receivers() or [])
            rec["providers"] = len(apk.get_providers() or [])
        except Exception:
            pass
        rec["cert"] = cert_info(apk)
    except Exception as e:
        rec["error"] = (rec["error"] + "; " if rec["error"] else "") + f"apk: {e}"

    # Normalize version_code to str for CSV friendliness later
    return rec


def to_cyclonedx(records: list[dict], fw_root: str) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    components = []
    deps = []
    for r in records:
        ref = str(uuid.uuid5(uuid.NAMESPACE_URL, "apk:" + r["path"]))
        pkg = r["package"] or r["file_name"]
        ver = r["version_name"] or "unknown"
        purl = f"pkg:apk/{pkg}@{ver}" if r["package"] else f"pkg:generic/{r['file_name']}@{ver}"
        props = [
            {"name": "apk:bom:source_path", "value": r["path"]},
            {"name": "apk:bom:version_code", "value": str(r["version_code"] or "")},
            {"name": "apk:bom:min_sdk", "value": str(r["min_sdk"] or "")},
            {"name": "apk:bom:target_sdk", "value": str(r["target_sdk"] or "")},
            {"name": "apk:bom:permission_count", "value": str(r["permission_count"])},
            {"name": "apk:bom:has_classes_dex", "value": str(r["has_dex"])},
            {"name": "apk:bom:odex_path", "value": r["odex_path"] or ""},
        ]
        if r["cert"].get("subject"):
            props.append({"name": "apk:bom:cert_subject", "value": r["cert"]["subject"]})
        if r["cert"].get("issuer"):
            props.append({"name": "apk:bom:cert_issuer", "value": r["cert"]["issuer"]})
        for perm in r["permissions"]:
            props.append({"name": "apk:bom:permission", "value": perm})
        for lib in r["native_libs"]:
            props.append({"name": "apk:bom:native_lib", "value": lib})
        for hint in r["lib_hints"]:
            props.append({"name": "apk:bom:lib_hint", "value": hint})

        comp = {
            "type": "application",
            "name": r["package"] or r["file_name"],
            "group": "android-apk",
            "version": ver,
            "bom-ref": ref,
            "purl": purl,
            "scope": "required",
            "hashes": [
                {"alg": "SHA-256", "content": r["sha256"]},
                {"alg": "MD5", "content": r["md5"]},
            ],
            "properties": props,
        }
        if r["package"]:
            cpe_app = r["package"].replace("_", "-").replace(".", "-")
            comp["cpe"] = f"cpe:2.3:a:{cpe_app}:{cpe_app}:{ver}:*:*:*:*:*:*:*"
        components.append(comp)
        deps.append({"ref": ref, "dependsOn": []})

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "custom", "name": "apk-bom-analyzer", "version": "1.0"}],
            "component": {
                "type": "firmware",
                "name": os.path.abspath(fw_root),
            },
        },
        "components": components,
        "dependencies": deps,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="APK BOM analyzer")
    ap.add_argument("root", nargs="?", default=".", help="firmware root to scan for *.apk")
    ap.add_argument("-o", "--outdir", default="apk_bom_out", help="output directory")
    args = ap.parse_args()

    apks = sorted(
        p for p in glob.glob(os.path.join(args.root, "**", "*.apk"), recursive=True)
        if os.path.isfile(p)
    )
    if not apks:
        print("No APK files found", file=sys.stderr)
        return 1

    os.makedirs(args.outdir, exist_ok=True)
    records = []
    for i, p in enumerate(apks, 1):
        print(f"[{i}/{len(apks)}] {p}", flush=True)
        records.append(analyze_apk(p))

    # CSV
    csv_path = os.path.join(args.outdir, "apk_bom.csv")
    fields = [
        "file_name", "package", "version_name", "version_code",
        "min_sdk", "target_sdk", "permission_count", "activities",
        "services", "receivers", "providers", "has_dex", "native_lib_count",
        "cert_subject", "cert_issuer", "odex_path", "lib_hints",
        "sha256", "md5", "size", "path", "error",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in records:
            w.writerow({
                "file_name": r["file_name"],
                "package": r["package"],
                "version_name": r["version_name"],
                "version_code": r["version_code"],
                "min_sdk": r["min_sdk"],
                "target_sdk": r["target_sdk"],
                "permission_count": r["permission_count"],
                "activities": r["activities"],
                "services": r["services"],
                "receivers": r["receivers"],
                "providers": r["providers"],
                "has_dex": r["has_dex"],
                "native_lib_count": r["native_lib_count"],
                "cert_subject": r["cert"].get("subject"),
                "cert_issuer": r["cert"].get("issuer"),
                "odex_path": r["odex_path"],
                "lib_hints": ";".join(r["lib_hints"]),
                "sha256": r["sha256"],
                "md5": r["md5"],
                "size": r["size"],
                "path": r["path"],
                "error": r["error"],
            })

    # Detailed JSON
    json_path = os.path.join(args.outdir, "apk_bom_detail.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)

    # CycloneDX
    cdx_path = os.path.join(args.outdir, "apk_bom_cyclonedx.json")
    cdx = to_cyclonedx(records, args.root)
    with open(cdx_path, "w", encoding="utf-8") as f:
        json.dump(cdx, f, indent=2, ensure_ascii=False)

    # Summary
    ok = [r for r in records if not r["error"]]
    with_pkg = [r for r in records if r["package"]]
    with_dex = [r for r in records if r["has_dex"]]
    with_odex = [r for r in records if r["odex_path"]]
    all_perms = sorted({p for r in records for p in r["permissions"]})
    all_hints = sorted({h for r in records for h in r["lib_hints"]})
    certs = sorted({(r["cert"].get("subject"), r["cert"].get("issuer")) for r in records if r["cert"].get("subject")})

    print("\n=== APK BOM Summary ===")
    print(f"APKs scanned     : {len(records)} (ok={len(ok)}, errors={len(records)-len(ok)})")
    print(f"with package name: {len(with_pkg)}")
    print(f"with classes.dex : {len(with_dex)}")
    print(f"with paired odex : {len(with_odex)}")
    print(f"unique permissions: {len(all_perms)}")
    print(f"lib hints found  : {', '.join(all_hints) or '-'}")
    print(f"unique certs     : {len(certs)}")
    for s, i in certs:
        print(f"  subject={s}")
        print(f"  issuer ={i}")
    print(f"\nOutputs:\n  {csv_path}\n  {json_path}\n  {cdx_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

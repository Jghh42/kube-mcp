#!/usr/bin/env python3
"""Validate the single-platform Docker/OCI archive handed between CI jobs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path
from typing import Any

SHA256_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
IMAGE_MANIFEST_MEDIA_TYPES = {
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
}
CONFIG_MEDIA_TYPES = {
    "application/vnd.docker.container.image.v1+json",
    "application/vnd.oci.image.config.v1+json",
}
LAYER_MEDIA_TYPE_FAMILIES = {
    "application/vnd.docker.image.rootfs.diff.tar": "tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip": "gzip",
    "application/vnd.oci.image.layer.v1.tar": "tar",
    "application/vnd.oci.image.layer.v1.tar+gzip": "gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd": "zstd",
}


class ArchiveError(ValueError):
    pass


def parse_json(data: bytes, description: str) -> Any:
    try:
        return json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ArchiveError(f"{description} is not valid JSON: {error}") from error


def sha256_digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def require_digest(value: Any, description: str) -> str:
    if not isinstance(value, str) or SHA256_DIGEST.fullmatch(value) is None:
        raise ArchiveError(f"{description} is not a sha256 digest")
    return value


def require_size(value: Any, description: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ArchiveError(f"{description} has an invalid size")
    return value


def load_archive_file(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    name: str,
) -> bytes:
    member = members.get(name)
    if member is None or not member.isfile():
        raise ArchiveError(f"archive is missing regular file {name}")
    stream = archive.extractfile(member)
    if stream is None:
        raise ArchiveError(f"cannot read archive file {name}")
    return stream.read()


def load_descriptor_blob(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    descriptor: Any,
    description: str,
) -> tuple[str, int, bytes]:
    if not isinstance(descriptor, dict):
        raise ArchiveError(f"{description} is not an object")
    digest = require_digest(descriptor.get("digest"), f"{description} digest")
    size = require_size(descriptor.get("size"), description)
    match = SHA256_DIGEST.fullmatch(digest)
    assert match is not None
    data = load_archive_file(archive, members, f"blobs/sha256/{match.group(1)}")
    if len(data) != size:
        raise ArchiveError(f"{description} size does not match its descriptor")
    if sha256_digest(data) != digest:
        raise ArchiveError(f"{description} content does not match {digest}")
    return digest, size, data


def descriptor_identity(
    descriptor: Any,
    description: str,
    descriptor_kind: str,
) -> tuple[str, int, str]:
    if not isinstance(descriptor, dict):
        raise ArchiveError(f"{description} is not an object")
    media_type = descriptor.get("mediaType")
    if descriptor_kind == "config":
        if media_type not in CONFIG_MEDIA_TYPES:
            raise ArchiveError(f"{description} has an invalid config media type")
        media_family = "config"
    elif descriptor_kind == "layer":
        media_family = LAYER_MEDIA_TYPE_FAMILIES.get(media_type)
        if media_family is None:
            raise ArchiveError(f"{description} has an unsupported layer media type")
    else:
        raise AssertionError(f"unexpected descriptor kind: {descriptor_kind}")
    return (
        require_digest(descriptor.get("digest"), f"{description} digest"),
        require_size(descriptor.get("size"), description),
        media_family,
    )


def validate_remote_manifest(
    path: Path,
    config_descriptor: tuple[str, int, str],
    layer_descriptors: list[tuple[str, int, str]],
) -> None:
    remote = parse_json(path.read_bytes(), "remote registry manifest")
    if not isinstance(remote, dict):
        raise ArchiveError("remote registry manifest is not an object")
    if remote.get("schemaVersion") != 2:
        raise ArchiveError("remote registry manifest does not use schema version 2")
    if remote.get("mediaType") not in IMAGE_MANIFEST_MEDIA_TYPES:
        raise ArchiveError("remote registry object is not a single image manifest")

    remote_config = descriptor_identity(
        remote.get("config"), "remote config", "config"
    )
    remote_layers_raw = remote.get("layers")
    if remote_layers_raw is None:
        remote_layers_raw = []
    if not isinstance(remote_layers_raw, list):
        raise ArchiveError("remote manifest layers is not an array")
    remote_layers = [
        descriptor_identity(item, f"remote layer {index}", "layer")
        for index, item in enumerate(remote_layers_raw)
    ]
    if remote_config != config_descriptor:
        raise ArchiveError("remote manifest does not reference the candidate config blob")
    if remote_layers != layer_descriptors:
        raise ArchiveError("remote manifest does not reference the candidate layers in order")


def validate_archive(
    path: Path,
    image: str,
    expected_manifest_digest: str | None,
    expected_config_digest: str | None,
    remote_manifest: Path | None,
) -> tuple[str, str]:
    if not path.is_file():
        raise ArchiveError(f"archive does not exist: {path}")

    with tarfile.open(path, mode="r:*") as archive:
        members: dict[str, tarfile.TarInfo] = {}
        for member in archive.getmembers():
            if member.name in members:
                raise ArchiveError(f"archive contains duplicate entry {member.name}")
            members[member.name] = member

        index = parse_json(
            load_archive_file(archive, members, "index.json"), "OCI index"
        )
        if not isinstance(index, dict) or index.get("schemaVersion") != 2:
            raise ArchiveError("archive index does not use OCI schema version 2")
        manifests = index.get("manifests")
        if not isinstance(manifests, list) or len(manifests) != 1:
            raise ArchiveError("archive must contain exactly one image manifest")

        root_descriptor = manifests[0]
        if not isinstance(root_descriptor, dict):
            raise ArchiveError("archive image descriptor is not an object")
        if root_descriptor.get("mediaType") not in IMAGE_MANIFEST_MEDIA_TYPES:
            raise ArchiveError("archive root is not an image manifest")
        platform = root_descriptor.get("platform")
        if not isinstance(platform, dict) or (
            platform.get("os"), platform.get("architecture")
        ) != ("linux", "amd64"):
            raise ArchiveError("archive image platform is not linux/amd64")

        manifest_digest, _, manifest_data = load_descriptor_blob(
            archive, members, root_descriptor, "image manifest"
        )
        manifest = parse_json(manifest_data, "image manifest")
        if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
            raise ArchiveError("image manifest does not use schema version 2")
        if manifest.get("mediaType") not in IMAGE_MANIFEST_MEDIA_TYPES:
            raise ArchiveError("archive blob is not an image manifest")

        config_raw = manifest.get("config")
        config_descriptor = descriptor_identity(config_raw, "image config", "config")
        config_digest, config_size, config_data = load_descriptor_blob(
            archive, members, config_raw, "image config"
        )
        if config_descriptor[:2] != (config_digest, config_size):
            raise AssertionError("validated config descriptor changed unexpectedly")
        config = parse_json(config_data, "image config")
        if not isinstance(config, dict) or (
            config.get("os"), config.get("architecture")
        ) != ("linux", "amd64"):
            raise ArchiveError("image config platform is not linux/amd64")

        layers_raw = manifest.get("layers")
        # BuildKit represents a valid zero-layer scratch image with null in its
        # Docker exporter; normalize that edge case to an empty descriptor list.
        if layers_raw is None:
            layers_raw = []
        if not isinstance(layers_raw, list):
            raise ArchiveError("image manifest layers is not an array")
        layer_descriptors: list[tuple[str, int, str]] = []
        for index, descriptor in enumerate(layers_raw):
            descriptor_value = descriptor_identity(
                descriptor, f"image layer {index}", "layer"
            )
            digest, size, _ = load_descriptor_blob(
                archive, members, descriptor, f"image layer {index}"
            )
            if descriptor_value[:2] != (digest, size):
                raise AssertionError("validated layer descriptor changed unexpectedly")
            layer_descriptors.append(descriptor_value)

        # BuildKit's Docker exporter includes this compatibility manifest. Check
        # that its tag and blob paths describe the same content-addressed graph.
        docker_manifest = parse_json(
            load_archive_file(archive, members, "manifest.json"),
            "Docker archive manifest",
        )
        if not isinstance(docker_manifest, list) or len(docker_manifest) != 1:
            raise ArchiveError("Docker archive manifest must contain one image")
        docker_image = docker_manifest[0]
        if not isinstance(docker_image, dict):
            raise ArchiveError("Docker archive image is not an object")
        repo_tags = docker_image.get("RepoTags")
        if not isinstance(repo_tags, list) or image not in repo_tags:
            raise ArchiveError(f"Docker archive does not contain expected tag {image}")
        config_path = f"blobs/sha256/{config_digest.removeprefix('sha256:')}"
        if docker_image.get("Config") != config_path:
            raise ArchiveError("Docker archive config does not match the OCI manifest")
        expected_layer_paths = [
            f"blobs/sha256/{digest.removeprefix('sha256:')}"
            for digest, _, _ in layer_descriptors
        ]
        docker_layers = docker_image.get("Layers")
        if docker_layers is None:
            docker_layers = []
        if docker_layers != expected_layer_paths:
            raise ArchiveError("Docker archive layers do not match the OCI manifest")

        if expected_manifest_digest is not None:
            require_digest(expected_manifest_digest, "expected manifest digest")
            if manifest_digest != expected_manifest_digest:
                raise ArchiveError("archive manifest digest does not match the expected digest")
        if expected_config_digest is not None:
            require_digest(expected_config_digest, "expected config digest")
            if config_digest != expected_config_digest:
                raise ArchiveError("archive config digest does not match the expected digest")
        if remote_manifest is not None:
            validate_remote_manifest(
                remote_manifest,
                config_descriptor,
                layer_descriptors,
            )

    return manifest_digest, config_digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--image", required=True)
    parser.add_argument("--expected-manifest-digest")
    parser.add_argument("--expected-config-digest")
    parser.add_argument("--remote-manifest", type=Path)
    args = parser.parse_args()

    try:
        manifest_digest, config_digest = validate_archive(
            args.archive,
            args.image,
            args.expected_manifest_digest,
            args.expected_config_digest,
            args.remote_manifest,
        )
    except (ArchiveError, OSError, tarfile.TarError) as error:
        print(f"invalid candidate image archive: {error}", file=sys.stderr)
        return 1

    # Line-oriented output is intentionally easy to consume with Bash mapfile.
    print(manifest_digest)
    print(config_digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

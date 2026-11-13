"""Translate verified Android service exports into native Shield records."""
import hashlib
import json
import re
from pathlib import Path

GENERIC_MAGIC = "scarlet-android-generic-exec-policy-v1"
# platform/system/core 83366e7e7a1556ab6cff117673bb9f17b973de99,
# libcutils/include/private/android_filesystem_config.h (android-13.0.0_r2).
AID_HEADER_SHA256 = "d6b164463418ba89aaf4ff9ce1367268fc0c6a6944b647c44905db65a40c0e5b"
# Digests of the four partitions in the pinned SDK input.
GENERIC_PARTITIONS = {
    "system": "cea78da8aafa4ef03c4fd993c0b1df2592286f7e5752e66a4aead7e439457217",
    "system_ext": "03106097e796f6e9e72d75c5a3fd4a395e197e7d59a04022a604d6d8a2885fe5",
    "product": "76dd3a2369c0da1b88a851432614688af33058f159fdf1434db4391693ba00d7",
    "vendor": "4222de4d8d0839d4550a15835cbe2fd7c42af90996357e6338e5605dbf3c2c52",
}

MAGIC = "scarlet-android-service-policy-v1"
ACCESS_MAGIC = "scarlet-android-access-policy-v2"
# /vendor/etc/selinux/precompiled_sepolicy in the SDK pinned by producer/lock.json.
SDK_POLICY_SHA256 = "2be08e2a2e93d22c6a1c5e4e32fa4d571ecb07695877cdcfe0c3a9f48ba9234c"
SDK_POLICY_VERSION = 30
MAX_NATIVE_LABELS = 2048

FILE_KINDS = {
    "file": 1,
    "dir": 2,
    "lnk_file": 3,
    "chr_file": 4,
    "blk_file": 5,
    "sock_file": 6,
    "fifo_file": 7,
}
FILE_RELABEL_EVIDENCE = re.compile(
    r"^allow (init|installd) ([A-Za-z0-9_]+):"
    r"(file|dir|lnk_file|chr_file|blk_file|sock_file|fifo_file) "
    r"(?:\{ ([a-z_ ]+) \}|([a-z_]+));$")


def policy_version(metadata):
    """Return the mapped version of the pinned Android source policy."""
    if not isinstance(metadata, dict):
        raise ValueError("service policy metadata")
    version = metadata.get("policy_version")
    if type(version) is not int or version != SDK_POLICY_VERSION:
        raise ValueError("service policy version")
    return version


def validate_metadata(metadata, text, source=None):
    """Bind a manager manifest to its exact generated and source bytes."""
    if not isinstance(metadata, dict):
        raise ValueError("service policy metadata")
    domains, rules = validate(text)
    version = policy_version(metadata)
    if (metadata.get("kind") != text.splitlines()[0] or
            metadata.get("text_sha256") != hashlib.sha256(text.encode()).hexdigest() or
            type(metadata.get("domains")) is not int or metadata["domains"] != len(domains) or
            type(metadata.get("rules")) is not int or metadata["rules"] != len(rules)):
        raise ValueError("changed service policy metadata")
    if metadata.get("source_sha256") != SDK_POLICY_SHA256:
        raise ValueError("service policy source")
    if source is not None and hashlib.sha256(source).hexdigest() != SDK_POLICY_SHA256:
        raise ValueError("changed service policy source")
    return version


def validate(text):
    if len(text.encode()) > 1024 * 1024 or not text.endswith("\n"):
        raise ValueError("service policy size or termination")
    lines = text.splitlines()
    if not lines or lines[0] not in (MAGIC, ACCESS_MAGIC):
        raise ValueError("service policy version")
    domains, rules = set(), {}
    for line in lines[1:]:
        fields = line.split()
        if len(fields) == 2 and fields[0] == "domain":
            name = fields[1]
            if not re.fullmatch(r"[A-Za-z0-9_]+", name) or name in domains:
                raise ValueError("service policy domain")
            domains.add(name)
        elif len(fields) == (5 if lines[0] == ACCESS_MAGIC else 4) and fields[0] == "allow":
            _, source, target, *values = fields
            kind, permissions = values if lines[0] == ACCESS_MAGIC else ("1", values[0])
            if (source not in domains or
                    not re.fullmatch(r"u:(r|object_r):[A-Za-z0-9_]+:s0", target) or
                    kind not in {"1", "2"} or kind == "2" and permissions != "1" or
                    permissions not in {"1", "2", "3", "4", "5", "6", "7"} or
                    (source, target, int(kind)) in rules):
                raise ValueError("service policy rule")
            rules[source, target, int(kind)] = int(permissions)
        else:
            raise ValueError("service policy record")
    if not domains or len(domains) > 256 or len(rules) > 16384:
        raise ValueError("service policy count")
    return domains, rules


def apply_boot_policy(boot, service_text, metadata=None):
    """Use the same compiled rules for existing boot subjects and future apps."""
    domains, grants = validate(service_text)
    version = validate_metadata(metadata, service_text) if metadata is not None else None
    labels, identifiers = {}, set()
    lines = boot.splitlines()
    if not lines or lines[0] not in ("scarlet-android-boot-policy-v1", "scarlet-android-boot-policy-v2"):
        raise ValueError("boot policy version")
    for line in lines:
        fields = line.split()
        if fields[:1] == ["label"]:
            if len(fields) != 3:
                raise ValueError("boot label syntax")
            identifier, name = int(fields[1]), fields[2]
            if name in labels or identifier in identifiers:
                raise ValueError("duplicate boot label")
            labels[name] = identifier
            identifiers.add(identifier)
    from .boot_profile import valid_context
    sources = {}
    for name, identifier in labels.items():
        if name.startswith("u:r:") and valid_context(name):
            domain = name.split(":")[2]
            if domain in domains:
                sources.setdefault(domain, set()).add(identifier)
    replaced = {identifier for identifiers in sources.values() for identifier in identifiers}
    replaced_kinds = ("service-allow ", "property-set ") if service_text.startswith(ACCESS_MAGIC + "\n") else ("service-allow ",)
    kept = [line for line in lines if not (line.startswith(replaced_kinds) and int(line.split()[1]) in replaced)]
    if version is not None:
        kept = [line for line in kept if not line.startswith("policy-version ")]
        kept.insert(1, f"policy-version {version}")
    next_id = max(identifiers, default=0) + 1
    added, rules = [], []
    for (source, target, kind), mask in sorted(grants.items()):
        if source not in sources:
            continue
        if target not in labels:
            labels[target] = next_id
            added.append(f"label {next_id} {target}")
            next_id += 1
        for identifier in sorted(sources[source]):
            rules.append(f"service-allow {identifier} {labels[target]} {mask}" if kind == 1 else f"property-set {identifier} {labels[target]}")
    if len(labels) > MAX_NATIVE_LABELS or sum(line.startswith(("service-allow ", "property-set ", "socket-create ", "keystore-allow ")) for line in kept) + len(rules) > 16384:
        raise ValueError("compiled service policy exceeds native policy bounds")
    return "\n".join(kept + added + rules) + "\n"


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def relabel_policy(manifest):
    """Return compact relabel matrices and non-compact exact fallbacks.

    Each evidence record is a concrete source/target/class allow. The
    relabelfrom values form origins and the relabelto values form destinations;
    SELinux evaluates those independently, so their cross product is the exact
    policy decision represented by the verified compiled policy. Exported
    destinations whose evidence remains an attribute, such as property_type,
    retain their exact exported pairs because the evidence does not enumerate
    that attribute's concrete members.
    """
    matrices = {}
    for line in manifest.get("file_relabel_evidence", []):
        match = FILE_RELABEL_EVIDENCE.fullmatch(line)
        if not match:
            raise ValueError("generic init relabel evidence")
        source, name, file_class, grouped, single = match.groups()
        permissions = set((grouped or single).split())
        key = (f"u:r:{source}:s0", FILE_KINDS[file_class])
        matrices.setdefault(key, {}).setdefault(name, set()).update(permissions)

    declared = {}
    exact_origins = {}
    for rule in manifest.get("file_relabels", []):
        if not isinstance(rule, list) or len(rule) != 4:
            raise ValueError("generic init file relabel")
        source, origin, target, kind = rule
        key = (source, kind)
        declared.setdefault(key, set()).add(target)
        exact_origins.setdefault(key, set()).add(origin)

    selected_names = {label.split(":")[2] for targets in declared.values() for label in targets}
    groups = {}
    for key, all_targets in declared.items():
        types = matrices.get(key, {})
        for origin in exact_origins[key]:
            name = origin.split(":")[2]
            if "relabelfrom" not in types.get(name, set()):
                raise ValueError("generic init file relabel lacks origin evidence")
        origins = {
            f"u:object_r:{name}:s0" for name, permissions in types.items()
            if "relabelfrom" in permissions and
            (name in selected_names or f"u:object_r:{name}:s0" in exact_origins[key])
        }
        targets = {label for label in all_targets
                   if label.split(":")[2] in types and "relabelto" in types[label.split(":")[2]]}
        if not origins or not targets:
            continue
        groups[key] = (tuple(sorted(origins)), tuple(sorted(targets)))

    exact = []
    for rule in manifest.get("file_relabels", []):
        group = groups.get((rule[0], rule[3]))
        if group is None or rule[2] not in group[1]:
            exact.append(rule)
    return groups, exact


def validate_generic(manifest):
    """Validate a byte-bound exported selection before adding native records."""
    value = dict(manifest)
    digest = value.pop("manifest_sha256", None)
    if digest != _digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()):
        raise ValueError("changed generic exec manifest")
    if (value.get("kind") != GENERIC_MAGIC or value.get("source_sha256") != SDK_POLICY_SHA256 or
            value.get("policy_version") != SDK_POLICY_VERSION or value.get("partitions") != GENERIC_PARTITIONS or
            value.get("aid_header_sha256") != AID_HEADER_SHA256):
        raise ValueError("generic exec provenance")
    from .boot_profile import relative_path, valid_context
    if not 1 <= len(value["services"]) <= 256 or len(value["rc_files"]) > 256:
        raise ValueError("generic manifest count")
    for name, digest in value["rc_files"].items():
        relative_path(name)
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("generic RC digest")
    files, transitions, direct, socket_rules, names = {}, set(), set(), set(), set()
    socket_count = 0
    for service in value["services"]:
        if (service["service"] in names or type(service["principal"]) is not int or
                not 0 <= service["principal"] <= 0xffffffff or
                value["rc_files"].get(service["rc"]) != service["rc_sha256"]):
            raise ValueError("generic service record")
        names.add(service["service"])
        sockets = service.get("sockets", [])
        if type(sockets) is not list or len(sockets) > 4096:
            raise ValueError("generic service sockets")
        socket_count += len(sockets)
        if socket_count > 4096:
            raise ValueError("generic service socket bound")
        socket_names = set()
        for socket in sockets:
            if (type(socket) is not dict or set(socket) != {"name", "type", "mode", "uid", "gid", "seclabel"} or
                    socket["name"] in socket_names or any(type(socket[key]) is not str or not socket[key]
                    for key in ("name", "type", "mode", "uid", "gid")) or
                    socket["seclabel"] is not None and (type(socket["seclabel"]) is not str or
                    not re.fullmatch(r"u:(r|object_r):[A-Za-z0-9_]+:s0", socket["seclabel"]))):
                raise ValueError("generic service socket record")
            socket_names.add(socket["name"])
        if service["disposition"] == "source-derived":
            path, label, target = service["resolved_executable"], service["file_label"], service["target"]
            relative_path(path.lstrip("/"))
            if (not path.startswith(("/system/", "/system_ext/", "/product/", "/vendor/", "/apex/")) or
                    not valid_context(label) or not label.startswith("u:object_r:") or
                    not re.fullmatch(r"u:r:[A-Za-z0-9_]+:s0", target) or
                    not re.fullmatch(r"[0-9a-f]{64}", service["executable_sha256"]) or
                    service["source_xattr_sha256"] != _digest((label + "\0").encode()) or not service["policy_rules"]):
                raise ValueError("generic source record")
            if path in files and files[path] != label:
                raise ValueError("generic file binding conflict")
            files[path] = label
            if service["seclabel"]:
                if service["seclabel"] != target:
                    raise ValueError("generic explicit target mismatch")
                direct.add(("u:r:init:s0", target, service["principal"]))
            else:
                transitions.add(("u:r:init:s0", label, target, service["principal"]))
            expected_sockets = sorted({socket["seclabel"] or target for socket in sockets})
            if service.get("socket_labels", []) != expected_sockets:
                raise ValueError("generic service socket delegation differs from options")
            socket_rules.update(("u:r:init:s0", socket_label) for socket_label in expected_sockets)
        elif service["disposition"] not in ("profile-managed", "optional-absent"):
            raise ValueError("generic disposition")
        elif service.get("socket_labels"):
            raise ValueError("generic managed service socket delegation")
    if (files != value["file_labels"] or sorted(transitions) != [tuple(rule) for rule in value["exec_transitions"]] or
            sorted(direct) != [tuple(rule) for rule in value["transitions"]] or
            value.get("socket_labels", []) != sorted(map(list, socket_rules))):
        raise ValueError("generic exec selection differs from evidence")
    relabels = value.get("file_relabels", [])
    evidence = value.get("file_relabel_evidence", [])
    if (not isinstance(relabels, list) or len(relabels) > 4096 or
            not isinstance(evidence, list) or len(evidence) > 4096 or
            bool(relabels) != bool(evidence) or
            any(not isinstance(line, str) or not re.match(r"allow (init|installd) ", line) or len(line) > 4096 for line in evidence)):
        raise ValueError("generic init relabel evidence")
    for rule in relabels:
        if (not isinstance(rule, list) or len(rule) != 4 or
                rule[0] not in ("u:r:init:s0", "u:r:installd:s0") or
                not isinstance(rule[1], str) or not re.fullmatch(r"u:object_r:[A-Za-z0-9_]+:s0", rule[1]) or
                not isinstance(rule[2], str) or not re.fullmatch(r"u:object_r:[A-Za-z0-9_]+:s0", rule[2]) or
                rule[2] == rule[1] or type(rule[3]) is not int or not 1 <= rule[3] <= 7):
            raise ValueError("generic init file relabel")
    if len({tuple(rule) for rule in relabels}) != len(relabels):
        raise ValueError("duplicate generic init file relabel")
    relabel_policy(value)
    creates=value.get("file_create_groups",[])
    evidence=value.get("file_create_evidence",[])
    if (not isinstance(creates,list) or len(creates)>42 or not isinstance(evidence,list) or len(evidence)>16384 or
            creates and not evidence or any(not isinstance(line,str) or not line.startswith("allow ") or len(line)>4096 for line in evidence)):
        raise ValueError("generic file creation evidence")
    seen=set()
    for group in creates:
        if (not isinstance(group,dict) or set(group)!={"source","parents","targets","kind"} or
                group["source"] not in {f"u:r:{source}:s0" for source in ("init","vendor_init","vold","apexd","installd","ueventd")} or
                type(group["kind"]) is not int or not 1<=group["kind"]<=7):
            raise ValueError("generic file creation group")
        for key in ("parents","targets"):
            names=group[key]
            if (not isinstance(names,list) or not names or len(names)>2048 or
                    any(not isinstance(name,str) or not re.fullmatch(r"u:object_r:[A-Za-z0-9_]+:s0",name) for name in names) or
                    names!=sorted(set(names))):raise ValueError("generic file creation labels")
        key=(group["source"],group["kind"])
        if key in seen:raise ValueError("duplicate generic file creation group")
        seen.add(key)
    return manifest


def apply_generic_boot_policy(boot, manifest, root=None):
    """Append verified launch, socket and label records with existing identifiers.

    Apply before apply_boot_policy() so the ordinary source service export also
    selects the newly registered daemon subjects. File content writes and
    service access are separate; sockets follow selected service declarations.
    """
    validate_generic(manifest)
    generic_relabels, exact_relabels = relabel_policy(manifest)
    if root is not None:
        from .inputs import sha256
        root = Path(root)
        for name, digest in manifest["rc_files"].items():
            if sha256(root / name) != digest:
                raise ValueError("changed generic RC during apply: " + name)
    lines = boot.splitlines()
    if not lines or lines[0] != "scarlet-android-boot-policy-v2":
        raise ValueError("generic exec requires boot policy v2")
    labels, ids, files, rules, direct, sockets, relabels = {}, set(), {}, {}, set(), set(), set()
    label_sets, set_members, set_rules = set(), {}, set()
    file_default = None
    for line in lines:
        fields = line.split()
        if fields[0] == "label":
            identifier = int(fields[1])
            if fields[2] in labels or identifier in ids:
                raise ValueError("duplicate generic boot label")
            labels[fields[2]], ids = identifier, ids | {identifier}
        elif fields[0] == "file-label":
            files[fields[2]] = int(fields[1])
        elif fields[0] == "file-exec":
            key = (int(fields[1]), int(fields[2]), int(fields[4]))
            rules[key] = int(fields[3])
        elif fields[0] == "transition":
            direct.add(tuple(map(int, fields[1:])))
        elif fields[0] == "socket-create":
            sockets.add((int(fields[1]), int(fields[2])))
        elif fields[0] == "file-default":
            file_default = int(fields[1])
        elif fields[0] == "file-relabel":
            relabels.add(tuple(map(int, fields[1:])))
        elif fields[0] == "label-set":label_sets.add(int(fields[1]))
        elif fields[0] == "set-member":set_members.setdefault(int(fields[1]),set()).add(int(fields[2]))
        elif fields[0] == "file-set":set_rules.add(tuple(map(int,fields[1:])))
    added = []
    def identifier(label):
        if label not in labels:
            labels[label] = max(ids, default=0) + 1
            ids.add(labels[label])
            added.append(f"label {labels[label]} {label}")
        return labels[label]
    def group_id(names):
        members={identifier(name) for name in names}
        for group in sorted(label_sets):
            if set_members.get(group,set())==members:return group
        group=max(label_sets,default=0)+1
        if group>0xffffffff:raise ValueError("native label set identity exhaustion")
        label_sets.add(group);set_members[group]=members
        added.append(f"label-set {group}")
        added.extend(f"set-member {group} {member}" for member in sorted(members))
        return group
    for path, label in sorted(manifest["file_labels"].items()):
        number = identifier(label)
        if path in files and files[path] != number:
            raise ValueError("generic binding conflicts with explicit profile: " + path)
        if path not in files:
            added.append(f"file-label {number} {path}")
            files[path] = number
    for source, resource, target, principal in manifest["exec_transitions"]:
        source, resource, target = map(identifier, (source, resource, target))
        key = (source, resource, principal)
        if key in rules and rules[key] != target:
            raise ValueError("generic transition conflicts with explicit profile")
        if key not in rules:
            added.append(f"file-exec {source} {resource} {target} {principal}")
            rules[key] = target
    for source, target, principal in manifest["transitions"]:
        rule = (identifier(source), identifier(target), principal)
        if rule not in direct:
            added.append("transition " + " ".join(map(str, rule)))
            direct.add(rule)
    for source, target in manifest.get("socket_labels", []):
        rule = (identifier(source), identifier(target))
        if rule not in sockets:
            added.append(f"socket-create {rule[0]} {rule[1]}")
            sockets.add(rule)
    if manifest.get("file_relabels") and file_default != labels.get("u:object_r:unlabeled:s0"):
        raise ValueError("init label restoration requires the matching native file default")
    for source, origin, target, kind in exact_relabels:
        rule = (identifier(source), identifier(origin), identifier(target), kind)
        if rule not in relabels:
            added.append("file-relabel " + " ".join(map(str, rule)))
            relabels.add(rule)
    for (source, kind), (origins, targets) in sorted(generic_relabels.items()):
        rule = (identifier(source), group_id(origins), group_id(targets), kind, 2, 1)
        if rule not in set_rules:
            added.append("file-set " + " ".join(map(str, rule)))
            set_rules.add(rule)
    if manifest.get("file_create_groups") and file_default is None:
        raise ValueError("file creation groups require a native file default")
    for group in manifest.get("file_create_groups",[]):
        rule=(identifier(group["source"]),group_id(group["parents"]),group_id(group["targets"]),group["kind"],1,0)
        if rule not in set_rules:
            added.append("file-set "+" ".join(map(str,rule)));set_rules.add(rule)
    if len(label_sets)>256 or sum(map(len,set_members.values()))>16384 or len(set_rules)>16384:
        raise ValueError("generic label set policy bound")
    if len(labels) > MAX_NATIVE_LABELS or len(files) > 4096 or len(rules) > 16384 or len(direct) > 16384 or len(sockets) > 16384 or len(relabels) > 16384:
        raise ValueError("generic native policy bound")
    return "\n".join(lines + added) + "\n"

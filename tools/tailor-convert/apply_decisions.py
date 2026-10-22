#!/usr/bin/env python3
"""
apply_decisions.py

Apply an environment-specific decisions.yml on top of a "gold" XCCDF
Tailoring file (the output of `usg generate-tailoring disa_stig tailor.xml`,
or any XCCDF 1.2 <Tailoring> document produced by usg for a given Ubuntu
release/benchmark), producing the tailor.xml that gets shipped in the BOSH
job template and consumed by:

    usg fix --tailoring-file tailor.xml
    usg audit --tailoring-file tailor.xml

Why this exists
----------------
usg's tailoring file has no native mechanism for tracking *why* a rule was
disabled or overridden, and hand-editing a 2,000+ line XCCDF file every time
the source benchmark is regenerated (e.g. STIG V1R1 -> V2R8, or a future
Ubuntu 24.04/Noble benchmark) is error-prone and loses institutional memory.

This script keeps the "why" (decisions.yml, keyed by stable rule name) and
the "what" (the gold tailoring file, regenerated from usg/ComplianceAsCode)
as separate, independently regenerable inputs, and merges them
deterministically with an audit trail:

  - Every decision is annotated as an XML comment directly above the
    <select>/<set-value> element it affects, so the rationale travels with
    the artifact that is actually consumed by usg.
  - Every decision that fails to match any rule in the gold file is reported
    as an error (not a silent no-op) -- this is what happens when the
    upstream benchmark renames or removes a rule between releases.
  - A summary is printed showing every change made, for use in a PR
    description / verification transcript.

Usage
-----
    python3 apply_decisions.py \
        --gold /path/to/gold-tailor.xml \
        --decisions decisions.yml \
        --output /path/to/tailor.xml

    # Dry run: show what would change without writing output
    python3 apply_decisions.py --gold gold-tailor.xml --decisions decisions.yml --check
"""

import argparse
import sys
from pathlib import Path

import yaml
from lxml import etree

XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"
NSMAP = {"xccdf": XCCDF_NS}

RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"
VALUE_PREFIX = "xccdf_org.ssgproject.content_value_"


def qname(local):
    return f"{{{XCCDF_NS}}}{local}"


def load_decisions(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    decisions = data.get("decisions", [])
    seen = set()
    for d in decisions:
        for key in ("rule", "action"):
            if key not in d:
                raise ValueError(f"decision missing required key '{key}': {d}")
        if d["action"] not in ("disable", "set-value", "accept"):
            raise ValueError(f"unknown action '{d['action']}' for rule '{d['rule']}'")
        if d["action"] == "set-value" and "value" not in d:
            raise ValueError(f"action 'set-value' requires 'value' for rule '{d['rule']}'")
        if d["rule"] in seen:
            raise ValueError(f"duplicate decision for rule '{d['rule']}'")
        seen.add(d["rule"])
    return decisions


def find_select_element(root, rule_name):
    idref = RULE_PREFIX + rule_name
    matches = root.findall(f".//{qname('select')}[@idref='{idref}']")
    if not matches:
        return None, idref
    if len(matches) > 1:
        raise ValueError(f"multiple <select> elements found for idref '{idref}'")
    return matches[0], idref


def find_setvalue_element(root, rule_name):
    idref = VALUE_PREFIX + rule_name
    matches = root.findall(f".//{qname('set-value')}[@idref='{idref}']")
    if not matches:
        return None, idref
    if len(matches) > 1:
        raise ValueError(f"multiple <set-value> elements found for idref '{idref}'")
    return matches[0], idref


def sanitize_for_xml_comment(text):
    """XML comments may not contain '--' or end with '-'."""
    text = text.replace("--", "-")
    text = text.rstrip()
    while text.endswith("-"):
        text = text[:-1].rstrip()
    return text


def make_comment_text(decision):
    stig_ids = decision.get("stig_ids", [])
    stig_str = f" [{', '.join(stig_ids)}]" if stig_ids else ""
    rationale = sanitize_for_xml_comment(decision.get("rationale", "").strip())
    return f" decisions.yml override{stig_str}: {rationale} "


def insert_comment_before(element, text):
    comment = etree.Comment(text)
    parent = element.getparent()
    parent.insert(parent.index(element), comment)


def apply_decision(root, decision, results):
    rule = decision["rule"]
    action = decision["action"]

    select_el, select_idref = find_select_element(root, rule)
    setvalue_el, setvalue_idref = find_setvalue_element(root, rule)

    if select_el is None and setvalue_el is None:
        results["errors"].append(
            f"rule '{rule}' not found in gold tailoring file "
            f"(looked for idref '{select_idref}' and '{setvalue_idref}'). "
            f"This usually means the rule was renamed or removed upstream -- "
            f"update decisions.yml to match the new rule name."
        )
        return

    if action == "accept":
        results["accepted"].append(rule)
        return

    if action == "disable":
        if select_el is None:
            results["errors"].append(
                f"rule '{rule}': action 'disable' requires a <select> element "
                f"but none was found (idref '{select_idref}')"
            )
            return
        before = select_el.get("selected")
        select_el.set("selected", "false")
        insert_comment_before(select_el, make_comment_text(decision))
        results["disabled"].append((rule, before, "false"))
        return

    if action == "set-value":
        if setvalue_el is None:
            results["errors"].append(
                f"rule '{rule}': action 'set-value' requires a <set-value> "
                f"element but none was found (idref '{setvalue_idref}')"
            )
            return
        before = setvalue_el.text
        setvalue_el.text = str(decision["value"])
        insert_comment_before(setvalue_el, make_comment_text(decision))
        results["set_values"].append((rule, before, decision["value"]))
        return


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold", required=True, help="Path to gold XCCDF Tailoring file")
    parser.add_argument("--decisions", required=True, help="Path to decisions.yml")
    parser.add_argument("--output", help="Path to write merged tailor.xml")
    parser.add_argument(
        "--check", action="store_true",
        help="Dry run: report what would change, do not write --output"
    )
    args = parser.parse_args()

    if not args.check and not args.output:
        parser.error("--output is required unless --check is given")

    gold_path = Path(args.gold)
    decisions_path = Path(args.decisions)

    if not gold_path.exists():
        print(f"error: gold tailoring file not found: {gold_path}", file=sys.stderr)
        return 1
    if not decisions_path.exists():
        print(f"error: decisions file not found: {decisions_path}", file=sys.stderr)
        return 1

    try:
        decisions = load_decisions(decisions_path)
    except (ValueError, yaml.YAMLError) as e:
        print(f"error: invalid decisions.yml: {e}", file=sys.stderr)
        return 1

    parser_xml = etree.XMLParser(remove_blank_text=False)
    tree = etree.parse(str(gold_path), parser_xml)
    root = tree.getroot()

    if root.tag != qname("Tailoring"):
        print(
            f"error: {gold_path} does not look like an XCCDF Tailoring file "
            f"(root element is '{root.tag}', expected '{{{XCCDF_NS}}}Tailoring'). "
            f"Generate one with: usg generate-tailoring disa_stig <output>",
            file=sys.stderr,
        )
        return 1

    results = {
        "disabled": [],
        "set_values": [],
        "accepted": [],
        "errors": [],
    }

    for decision in decisions:
        apply_decision(root, decision, results)

    print(f"Gold tailoring file : {gold_path}")
    print(f"Decisions file      : {decisions_path}")
    print(f"Total decisions     : {len(decisions)}")
    print()

    if results["disabled"]:
        print(f"Disabled ({len(results['disabled'])}):")
        for rule, before, after in results["disabled"]:
            print(f"  - {rule}: selected={before!r} -> selected={after!r}")
        print()

    if results["set_values"]:
        print(f"Set-value overrides ({len(results['set_values'])}):")
        for rule, before, after in results["set_values"]:
            print(f"  - {rule}: {before!r} -> {after!r}")
        print()

    if results["accepted"]:
        print(f"Accepted as-is ({len(results['accepted'])}):")
        for rule in results["accepted"]:
            print(f"  - {rule}")
        print()

    if results["errors"]:
        print(f"ERRORS ({len(results['errors'])}):", file=sys.stderr)
        for err in results["errors"]:
            print(f"  - {err}", file=sys.stderr)
        print(file=sys.stderr)
        print(
            "Refusing to write output: unresolved decisions must be fixed "
            "before this tailoring file can be trusted.",
            file=sys.stderr,
        )
        return 1

    if args.check:
        print("Dry run (--check): no output written.")
        return 0

    output_path = Path(args.output)
    tree.write(
        str(output_path),
        xml_declaration=True,
        encoding="UTF-8",
        standalone=None,
    )
    print(f"Wrote merged tailoring file: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

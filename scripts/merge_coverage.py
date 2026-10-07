"""Combine line coverage from normal and privileged runs of the same commit.

The union retains uncovered lines from every input. Duplicate class entries do
not count source lines twice. This report measures lines, not branch coverage.
"""
import argparse
from pathlib import Path, PurePosixPath
import xml.etree.ElementTree as ET


def source_name(value):
    if not value:
        raise ValueError("Coverage class has no source filename")
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute():
        try:
            path = PurePosixPath(Path(str(path)).resolve().relative_to(Path.cwd().resolve()).as_posix())
        except ValueError as error:
            raise ValueError("Coverage source is outside this checkout") from error
    if not path.parts or ".." in path.parts or ":" in path.parts[0]:
        raise ValueError("Coverage source must be a checkout-relative path")
    return str(path)


def read_report(path):
    root = ET.parse(path).getroot()
    files = {}
    for cls in root.iter("class"):
        filename = source_name(cls.get("filename"))
        group = cls.find("lines")
        if group is None:
            raise ValueError("Coverage class has no line records")
        lines = files.setdefault(filename, {})
        for line in group.findall("line"):
            try:
                number = int(line.attrib["number"])
                hits = int(line.attrib["hits"])
            except (KeyError, ValueError) as error:
                raise ValueError("Invalid coverage line record") from error
            if number <= 0 or hits < 0:
                raise ValueError("Coverage line numbers must be positive and hits nonnegative")
            lines[number] = max(lines.get(number, 0), hits)
    if not any(files.values()):
        raise ValueError("Coverage report contains no source lines")
    return files


def merge_reports(output, inputs):
    output = Path(output)
    inputs = [Path(path) for path in inputs]
    if len(inputs) < 2 or len({path.resolve() for path in inputs}) != len(inputs):
        raise ValueError("Provide at least two distinct coverage reports")
    if output.resolve() in {path.resolve() for path in inputs}:
        raise ValueError("The merged report must not overwrite an input")
    files = {}
    for path in inputs:
        for filename, incoming in read_report(path).items():
            lines = files.setdefault(filename, {})
            for number, hits in incoming.items():
                lines[number] = lines.get(number, 0) + hits
    total = sum(len(lines) for lines in files.values())
    covered = sum(hits > 0 for lines in files.values() for hits in lines.values())
    rate = str(covered / total)
    attributes = {"line-rate": rate, "branch-rate": "0", "complexity": "0"}
    root = ET.Element("coverage", dict(attributes, **{
        "lines-valid": str(total), "lines-covered": str(covered),
        "branches-valid": "0", "branches-covered": "0", "version": "line-union-1",
    }))
    ET.SubElement(ET.SubElement(root, "sources"), "source").text = str(Path.cwd().resolve())
    package = ET.SubElement(ET.SubElement(root, "packages"), "package", dict(attributes, name="combined"))
    classes = ET.SubElement(package, "classes")
    for filename, records in sorted(files.items()):
        hits = sum(value > 0 for value in records.values())
        cls = ET.SubElement(classes, "class", {
            "name": filename, "filename": filename,
            "line-rate": str(hits / len(records)) if records else "0",
            "branch-rate": "0", "complexity": "0",
        })
        ET.SubElement(cls, "methods")
        lines = ET.SubElement(cls, "lines")
        for number, count in sorted(records.items()):
            ET.SubElement(lines, "line", {"number": str(number), "hits": str(count)})
    output.parent.mkdir(parents=True, exist_ok=True)
    ET.indent(root)
    ET.ElementTree(root).write(output, encoding="utf-8", xml_declaration=True)
    return covered, total


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    parser.add_argument("inputs", nargs="+")
    args = parser.parse_args()
    covered, total = merge_reports(args.output, args.inputs)
    print(f"Merged line coverage: {covered}/{total} ({100 * covered / total:.2f}%)")

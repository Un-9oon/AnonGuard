"""Coverage aggregation must preserve missing lines and refuse malformed evidence."""
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET
from merge_coverage import merge_reports


class CoverageMergeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def report(self, name, classes):
        root = ET.Element("coverage")
        group = ET.SubElement(root, "classes")
        for filename, records in classes:
            cls = ET.SubElement(group, "class", {"filename": filename})
            lines = ET.SubElement(cls, "lines")
            for number, hits in records:
                ET.SubElement(lines, "line", {"number": str(number), "hits": str(hits)})
        path = self.directory / name
        ET.ElementTree(root).write(path)
        return path

    def test_union_keeps_uncovered_lines_and_disjoint_sources(self):
        first = self.report("first.xml", [("src/mesh/a.rs", [(1, 2), (2, 0)]), ("src/b.rs", [(10, 0)])])
        second = self.report("second.xml", [("src/mesh/a.rs", [(1, 0), (2, 3), (3, 0)]), ("src/c.rs", [(4, 1)])])
        output = self.directory / "merged.xml"
        self.assertEqual(merge_reports(output, [first, second]), (3, 5))
        root = ET.parse(output).getroot()
        self.assertEqual(root.get("lines-valid"), "5")
        self.assertEqual(root.get("lines-covered"), "3")
        self.assertEqual(float(root.get("line-rate")), 0.6)
        classes = {cls.get("filename"): cls for cls in root.iter("class")}
        self.assertEqual(set(classes), {"src/mesh/a.rs", "src/b.rs", "src/c.rs"})
        self.assertEqual([(line.get("number"), line.get("hits")) for line in classes["src/mesh/a.rs"].iter("line")], [("1", "2"), ("2", "3"), ("3", "0")])

    def test_duplicate_classes_do_not_duplicate_source_lines(self):
        first = self.report("first.xml", [("src/a.rs", [(1, 2)]), ("./src/a.rs", [(1, 3), (2, 0)])])
        second = self.report("second.xml", [("src/a.rs", [(1, 4)])])
        output = self.directory / "merged.xml"
        self.assertEqual(merge_reports(output, [first, second]), (1, 2))
        self.assertEqual(next(ET.parse(output).getroot().iter("line")).get("hits"), "7")

    def test_invalid_records_and_outside_sources_are_rejected(self):
        good = self.report("good.xml", [("src/a.rs", [(1, 1)])])
        for filename, records in [("src/a.rs", [(0, 1)]), ("src/a.rs", [(1, -1)]), ("../outside.rs", [(1, 1)]), ("", [(1, 1)]), (".", [(1, 1)]), ("/outside.rs", [(1, 1)])]:
            with self.subTest(filename=filename, records=records):
                bad = self.report("bad.xml", [(filename, records)])
                with self.assertRaises(ValueError):
                    merge_reports(self.directory / "merged.xml", [good, bad])

    def test_empty_and_missing_line_evidence_is_rejected(self):
        good = self.report("good.xml", [("src/a.rs", [(1, 1)])])
        empty = self.report("empty.xml", [])
        with self.assertRaises(ValueError):
            merge_reports(self.directory / "merged.xml", [good, empty])
        missing = self.directory / "missing.xml"
        missing.write_text('<coverage><class filename="src/a.rs"/></coverage>')
        with self.assertRaises(ValueError):
            merge_reports(self.directory / "merged.xml", [good, missing])

    def test_input_artifacts_are_preserved(self):
        first = self.report("first.xml", [("src/a.rs", [(1, 1)])])
        second = self.report("second.xml", [("src/a.rs", [(1, 0)])])
        before = first.read_bytes()
        with self.assertRaises(ValueError):
            merge_reports(first, [first, second])
        self.assertEqual(first.read_bytes(), before)
        with self.assertRaises(ValueError):
            merge_reports(self.directory / "merged.xml", [first, first])


if __name__ == "__main__":
    unittest.main()

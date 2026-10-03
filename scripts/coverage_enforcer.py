import xml.etree.ElementTree as ET
import sys
import sys

def check_coverage(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    overall_line_rate = float(root.attrib.get('line-rate', 0.0))
    overall_pct = overall_line_rate * 100

    print(f"Overall Coverage: {overall_pct:.2f}%")
    if overall_pct < 80.0:
        print("ERROR: Overall coverage below 80%.")
        sys.exit(1)

    # Check packages/classes
    mesh_lines = 0
    mesh_hits = 0
    onion_lines = 0
    onion_hits = 0

    for cls in root.iter('class'):
        filename = cls.attrib.get('filename', '')
        lines = list(cls.find('lines').iter('line'))
        cls_hits = sum(1 for line in lines if int(line.attrib.get('hits', 0)) > 0)
        cls_total = len(lines)

        if 'src/mesh/' in filename:
            mesh_lines += cls_total
            mesh_hits += cls_hits
        elif 'src/onion/' in filename:
            onion_lines += cls_total
            onion_hits += cls_hits

    def report(name, hits, total, threshold):
        if total == 0:
            print(f"{name}: No lines found.")
            return True
        pct = (hits / total) * 100
        print(f"{name} Coverage: {pct:.2f}% ({hits}/{total})")
        if pct < threshold:
            print(f"ERROR: {name} coverage is {pct:.2f}%, below {threshold}%.")
            return False
        return True

    success = True
    success &= report('src/mesh/', mesh_hits, mesh_lines, 90.0)
    success &= report('src/onion/', onion_hits, onion_lines, 90.0)

    if not success:
        sys.exit(1)
    
    print("Coverage checks passed.")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python coverage_enforcer.py <cobertura.xml>")
        sys.exit(1)
    check_coverage(sys.argv[1])

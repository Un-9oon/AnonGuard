import os
import re

def process_file(filepath):
    in_test_mod = False
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    results = []
    brace_count = 0
    for i, line in enumerate(lines):
        if re.search(r'#\[cfg\(test\)\]', line) or (re.search(r'mod tests\s*\{', line) and not in_test_mod):
            in_test_mod = True
            brace_count = line.count('{') - line.count('}')
            continue
        
        if in_test_mod:
            brace_count += line.count('{') - line.count('}')
            if brace_count <= 0:
                in_test_mod = False
            continue
            
        if re.search(r'\b(unwrap|expect|panic!)\b', line) and not line.strip().startswith('//'):
            results.append(f"{filepath}:{i+1}:{line.strip()}")
            
    return results

for root, _, files in os.walk('src'):
    for file in files:
        if file.endswith('.rs'):
            res = process_file(os.path.join(root, file))
            for r in res:
                print(r)

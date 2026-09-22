import re
d = open(r'src\payload\adapters\present_hook.cpp').read()
d2 = re.sub(r'"(?:[^"\\]|\\.)*"', '""', d)
d2 = re.sub(r"'(?:[^'\\]|\\.)*'", "''", d2)
d2 = re.sub(r'//.*', '', d2)
d2 = re.sub(r'/\*.*?\*/', '', d2, flags=re.S)
print('open:', d2.count('{'), 'close:', d2.count('}'))
depth = 0
for i, line in enumerate(d2.splitlines(), 1):
    depth += line.count('{') - line.count('}')
    if depth < 0:
        print('negative at', i, line.strip()[:80])
        break
print('final depth:', depth)

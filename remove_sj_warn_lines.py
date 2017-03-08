import sys
import re

regex = re.compile(r'\t')
print("Working...")
with open(sys.argv[1]) as old, open(sys.argv[2], "w") as new:
    for line in old:
        if(regex.search(line)):
            new.write(line)

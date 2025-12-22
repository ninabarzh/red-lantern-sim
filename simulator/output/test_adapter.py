# simulator/output/test_adapter.py
import sys
import json
from .adapter import ScenarioAdapter

def main():
    adapter = ScenarioAdapter()
    for line in sys.stdin:
        try:
            event = json.loads(line)
            for log_line in adapter.transform(event):
                print(log_line)
        except json.JSONDecodeError:
            continue

if __name__ == "__main__":
    main()

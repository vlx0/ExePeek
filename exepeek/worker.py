"""Cancellable helper process: native Windows trust checks cannot be interrupted safely in a thread."""
import json
import sys
from .core import inspect_file


def main():
    try:
        result = {'result':inspect_file(sys.argv[1])}
    except Exception as exc:
        result = {'error':str(exc)}
    sys.stdout.buffer.write(json.dumps(result, ensure_ascii=True).encode('utf-8'))
    sys.stdout.buffer.flush()


if __name__ == '__main__':
    main()

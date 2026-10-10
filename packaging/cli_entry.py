import multiprocessing
import sys

from otinspect.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())

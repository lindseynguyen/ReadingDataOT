import sys

if len(sys.argv) > 1 and sys.argv[1] == "gui":
    from .gui.app import main as gui_main
    sys.exit(gui_main())

from .cli import main

sys.exit(main())

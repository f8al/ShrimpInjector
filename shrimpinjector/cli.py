import argparse
import sys

from shrimpinjector import __version__
from shrimpinjector.payloads import PAYLOAD_BUILDERS, PAYLOAD_DESCRIPTIONS


def print_banner():
    p = lambda s: print(s, file=sys.stderr)
    p("\x1b[0m")
    p("╔═══════════════════════════════════════════════════ ShrimpInjector ════════════════════════════════════════════════════╗")
    p("║ \x1b[38;5;202m \x1b[38;5;202m \x1b[38;5;202m█\x1b[38;5;203m█\x1b[38;5;203m█\x1b[38;5;203m█\x1b[38;5;203m█\x1b[38;5;203m█\x1b[38;5;204m \x1b[38;5;204m \x1b[38;5;204m█\x1b[38;5;204m█\x1b[38;5;204m░\x1b[38;5;205m \x1b[38;5;205m█\x1b[38;5;205m█\x1b[38;5;205m \x1b[38;5;206m \x1b[38;5;206m█\x1b[38;5;206m█\x1b[38;5;206m▀\x1b[38;5;206m█\x1b[38;5;207m█\x1b[38;5;207m█\x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;208m█\x1b[38;5;208m█\x1b[38;5;208m▓\x1b[38;5;208m \x1b[38;5;208m█\x1b[38;5;209m█\x1b[38;5;209m█\x1b[38;5;209m▄\x1b[38;5;209m \x1b[38;5;209m▄\x1b[38;5;210m█\x1b[38;5;210m█\x1b[38;5;210m█\x1b[38;5;210m▓\x1b[38;5;210m \x1b[38;5;211m█\x1b[38;5;211m█\x1b[38;5;211m▓\x1b[38;5;211m█\x1b[38;5;212m█\x1b[38;5;212m█\x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;213m█\x1b[38;5;213m█\x1b[38;5;213m▓\x1b[38;5;213m \x1b[38;5;213m█\x1b[38;5;214m█\x1b[38;5;214m█\x1b[38;5;214m▄\x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;215m \x1b[38;5;215m \x1b[38;5;215m█\x1b[38;5;215m \x1b[38;5;215m \x1b[38;5;216m▄\x1b[38;5;216m▄\x1b[38;5;216m▄\x1b[38;5;216m█\x1b[38;5;216m█\x1b[38;5;217m▀\x1b[38;5;217m▀\x1b[38;5;217m▀\x1b[38;5;217m▓\x1b[38;5;218m█\x1b[38;5;218m█\x1b[38;5;218m█\x1b[38;5;218m█\x1b[38;5;218m█\x1b[38;5;219m \x1b[38;5;219m \x1b[38;5;219m▄\x1b[38;5;219m█\x1b[38;5;219m█\x1b[38;5;220m█\x1b[38;5;220m█\x1b[38;5;220m▄\x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;221m▄\x1b[38;5;221m▄\x1b[38;5;221m▄\x1b[38;5;221m█\x1b[38;5;221m█\x1b[38;5;222m█\x1b[38;5;222m█\x1b[38;5;222m█\x1b[38;5;222m▓\x1b[38;5;222m \x1b[38;5;223m▒\x1b[38;5;223m█\x1b[38;5;223m█\x1b[38;5;223m█\x1b[38;5;224m█\x1b[38;5;224m█\x1b[38;5;224m \x1b[38;5;224m \x1b[38;5;224m \x1b[38;5;225m█\x1b[38;5;225m█\x1b[38;5;225m▀\x1b[38;5;225m█\x1b[38;5;225m█\x1b[38;5;226m█\x1b[38;5;226m \x1b[38;5;226m \x1b[0m ║")
    p("║ \x1b[38;5;202m▒\x1b[38;5;202m█\x1b[38;5;202m█\x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;203m▒\x1b[38;5;204m \x1b[38;5;204m▓\x1b[38;5;204m█\x1b[38;5;204m█\x1b[38;5;204m░\x1b[38;5;205m \x1b[38;5;205m█\x1b[38;5;205m█\x1b[38;5;205m▒\x1b[38;5;206m▓\x1b[38;5;206m█\x1b[38;5;206m█\x1b[38;5;206m \x1b[38;5;206m▒\x1b[38;5;207m \x1b[38;5;207m█\x1b[38;5;207m█\x1b[38;5;207m▒\x1b[38;5;207m▓\x1b[38;5;208m█\x1b[38;5;208m█\x1b[38;5;208m▒\x1b[38;5;208m▓\x1b[38;5;208m█\x1b[38;5;209m█\x1b[38;5;209m▒\x1b[38;5;209m▀\x1b[38;5;209m█\x1b[38;5;209m▀\x1b[38;5;210m \x1b[38;5;210m█\x1b[38;5;210m█\x1b[38;5;210m▒\x1b[38;5;210m▓\x1b[38;5;211m█\x1b[38;5;211m█\x1b[38;5;211m░\x1b[38;5;211m \x1b[38;5;212m \x1b[38;5;212m█\x1b[38;5;212m█\x1b[38;5;212m▒\x1b[38;5;212m▓\x1b[38;5;213m█\x1b[38;5;213m█\x1b[38;5;213m▒\x1b[38;5;213m \x1b[38;5;213m█\x1b[38;5;214m█\x1b[38;5;214m \x1b[38;5;214m▀\x1b[38;5;214m█\x1b[38;5;214m \x1b[38;5;215m \x1b[38;5;215m \x1b[38;5;215m█\x1b[38;5;215m \x1b[38;5;215m \x1b[38;5;216m \x1b[38;5;216m \x1b[38;5;216m▒\x1b[38;5;216m█\x1b[38;5;216m█\x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m▓\x1b[38;5;218m█\x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;218m▀\x1b[38;5;219m \x1b[38;5;219m▒\x1b[38;5;219m█\x1b[38;5;219m█\x1b[38;5;219m▀\x1b[38;5;220m \x1b[38;5;220m▀\x1b[38;5;220m█\x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;221m▓\x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;221m█\x1b[38;5;221m█\x1b[38;5;222m▒\x1b[38;5;222m \x1b[38;5;222m▓\x1b[38;5;222m▒\x1b[38;5;222m▒\x1b[38;5;223m█\x1b[38;5;223m█\x1b[38;5;223m▒\x1b[38;5;223m \x1b[38;5;224m \x1b[38;5;224m█\x1b[38;5;224m█\x1b[38;5;224m▒\x1b[38;5;224m▓\x1b[38;5;225m█\x1b[38;5;225m█\x1b[38;5;225m \x1b[38;5;225m▒\x1b[38;5;225m \x1b[38;5;226m█\x1b[38;5;226m█\x1b[38;5;226m▒\x1b[0m ║")
    p("║ \x1b[38;5;202m░\x1b[38;5;202m \x1b[38;5;202m▓\x1b[38;5;203m█\x1b[38;5;203m█\x1b[38;5;203m▄\x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;204m \x1b[38;5;204m▒\x1b[38;5;204m█\x1b[38;5;204m█\x1b[38;5;204m▀\x1b[38;5;205m▀\x1b[38;5;205m█\x1b[38;5;205m█\x1b[38;5;205m░\x1b[38;5;206m▓\x1b[38;5;206m█\x1b[38;5;206m█\x1b[38;5;206m \x1b[38;5;206m░\x1b[38;5;207m▄\x1b[38;5;207m█\x1b[38;5;207m \x1b[38;5;207m▒\x1b[38;5;207m▒\x1b[38;5;208m█\x1b[38;5;208m█\x1b[38;5;208m▒\x1b[38;5;208m▓\x1b[38;5;208m█\x1b[38;5;209m█\x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;210m▓\x1b[38;5;210m█\x1b[38;5;210m█\x1b[38;5;210m░\x1b[38;5;210m▓\x1b[38;5;211m█\x1b[38;5;211m█\x1b[38;5;211m░\x1b[38;5;211m \x1b[38;5;212m█\x1b[38;5;212m█\x1b[38;5;212m▓\x1b[38;5;212m▒\x1b[38;5;212m▒\x1b[38;5;213m█\x1b[38;5;213m█\x1b[38;5;213m▒\x1b[38;5;213m▓\x1b[38;5;213m█\x1b[38;5;214m█\x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;214m▀\x1b[38;5;214m█\x1b[38;5;215m \x1b[38;5;215m█\x1b[38;5;215m█\x1b[38;5;215m▒\x1b[38;5;215m \x1b[38;5;216m \x1b[38;5;216m \x1b[38;5;216m░\x1b[38;5;216m█\x1b[38;5;216m█\x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m▒\x1b[38;5;218m█\x1b[38;5;218m█\x1b[38;5;218m█\x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;219m \x1b[38;5;219m▒\x1b[38;5;219m▓\x1b[38;5;219m█\x1b[38;5;219m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;220m▄\x1b[38;5;220m \x1b[38;5;221m▒\x1b[38;5;221m \x1b[38;5;221m▓\x1b[38;5;221m█\x1b[38;5;221m█\x1b[38;5;222m░\x1b[38;5;222m \x1b[38;5;222m▒\x1b[38;5;222m░\x1b[38;5;222m▒\x1b[38;5;223m█\x1b[38;5;223m█\x1b[38;5;223m░\x1b[38;5;223m \x1b[38;5;224m \x1b[38;5;224m█\x1b[38;5;224m█\x1b[38;5;224m▒\x1b[38;5;224m▓\x1b[38;5;225m█\x1b[38;5;225m█\x1b[38;5;225m \x1b[38;5;225m░\x1b[38;5;225m▄\x1b[38;5;226m█\x1b[38;5;226m \x1b[38;5;226m▒\x1b[0m ║")
    p("║ \x1b[38;5;202m \x1b[38;5;202m \x1b[38;5;202m▒\x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;203m█\x1b[38;5;203m█\x1b[38;5;204m▒\x1b[38;5;204m░\x1b[38;5;204m▓\x1b[38;5;204m█\x1b[38;5;204m \x1b[38;5;205m░\x1b[38;5;205m█\x1b[38;5;205m█\x1b[38;5;205m \x1b[38;5;206m▒\x1b[38;5;206m█\x1b[38;5;206m█\x1b[38;5;206m▀\x1b[38;5;206m▀\x1b[38;5;207m█\x1b[38;5;207m▄\x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;207m░\x1b[38;5;208m█\x1b[38;5;208m█\x1b[38;5;208m░\x1b[38;5;208m▒\x1b[38;5;208m█\x1b[38;5;209m█\x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;210m▒\x1b[38;5;210m█\x1b[38;5;210m█\x1b[38;5;210m \x1b[38;5;210m▒\x1b[38;5;211m█\x1b[38;5;211m█\x1b[38;5;211m▄\x1b[38;5;211m█\x1b[38;5;212m▓\x1b[38;5;212m▒\x1b[38;5;212m \x1b[38;5;212m▒\x1b[38;5;212m░\x1b[38;5;213m█\x1b[38;5;213m█\x1b[38;5;213m░\x1b[38;5;213m▓\x1b[38;5;213m█\x1b[38;5;214m█\x1b[38;5;214m▒\x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;214m┌\x1b[38;5;215m▌\x1b[38;5;215m█\x1b[38;5;215m█\x1b[38;5;215m▒\x1b[38;5;215m▓\x1b[38;5;216m█\x1b[38;5;216m█\x1b[38;5;216m▄\x1b[38;5;216m█\x1b[38;5;216m█\x1b[38;5;217m▓\x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m▒\x1b[38;5;218m▓\x1b[38;5;218m█\x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;218m▄\x1b[38;5;219m \x1b[38;5;219m▒\x1b[38;5;219m▓\x1b[38;5;219m▓\x1b[38;5;219m▄\x1b[38;5;220m \x1b[38;5;220m▄\x1b[38;5;220m█\x1b[38;5;220m█\x1b[38;5;220m▒\x1b[38;5;221m░\x1b[38;5;221m \x1b[38;5;221m▓\x1b[38;5;221m█\x1b[38;5;221m█\x1b[38;5;222m▓\x1b[38;5;222m \x1b[38;5;222m░\x1b[38;5;222m \x1b[38;5;222m▒\x1b[38;5;223m█\x1b[38;5;223m█\x1b[38;5;223m \x1b[38;5;223m \x1b[38;5;224m \x1b[38;5;224m█\x1b[38;5;224m█\x1b[38;5;224m░\x1b[38;5;224m▒\x1b[38;5;225m█\x1b[38;5;225m█\x1b[38;5;225m▀\x1b[38;5;225m▀\x1b[38;5;225m█\x1b[38;5;226m▄\x1b[38;5;226m \x1b[38;5;226m \x1b[0m ║")
    p("║ \x1b[38;5;202m▒\x1b[38;5;202m█\x1b[38;5;202m█\x1b[38;5;203m█\x1b[38;5;203m█\x1b[38;5;203m█\x1b[38;5;203m█\x1b[38;5;203m▒\x1b[38;5;204m▒\x1b[38;5;204m░\x1b[38;5;204m▓\x1b[38;5;204m█\x1b[38;5;204m▒\x1b[38;5;205m░\x1b[38;5;205m█\x1b[38;5;205m█\x1b[38;5;205m▓\x1b[38;5;206m░\x1b[38;5;206m█\x1b[38;5;206m█\x1b[38;5;206m▓\x1b[38;5;206m \x1b[38;5;207m▒\x1b[38;5;207m█\x1b[38;5;207m█\x1b[38;5;207m▒\x1b[38;5;207m░\x1b[38;5;208m█\x1b[38;5;208m█\x1b[38;5;208m░\x1b[38;5;208m▒\x1b[38;5;208m█\x1b[38;5;209m█\x1b[38;5;209m▒\x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;210m░\x1b[38;5;210m█\x1b[38;5;210m█\x1b[38;5;210m▒\x1b[38;5;210m▒\x1b[38;5;211m█\x1b[38;5;211m█\x1b[38;5;211m▒\x1b[38;5;211m \x1b[38;5;212m░\x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m░\x1b[38;5;212m░\x1b[38;5;213m█\x1b[38;5;213m█\x1b[38;5;213m░\x1b[38;5;213m▒\x1b[38;5;213m█\x1b[38;5;214m█\x1b[38;5;214m░\x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;215m▓\x1b[38;5;215m█\x1b[38;5;215m█\x1b[38;5;215m░\x1b[38;5;215m \x1b[38;5;216m▓\x1b[38;5;216m█\x1b[38;5;216m█\x1b[38;5;216m█\x1b[38;5;216m▒\x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m░\x1b[38;5;218m▒\x1b[38;5;218m█\x1b[38;5;218m█\x1b[38;5;218m█\x1b[38;5;218m█\x1b[38;5;219m▒\x1b[38;5;219m▒\x1b[38;5;219m \x1b[38;5;219m▓\x1b[38;5;219m█\x1b[38;5;220m█\x1b[38;5;220m█\x1b[38;5;220m▀\x1b[38;5;220m \x1b[38;5;220m░\x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;221m▒\x1b[38;5;221m█\x1b[38;5;221m█\x1b[38;5;222m▒\x1b[38;5;222m \x1b[38;5;222m░\x1b[38;5;222m \x1b[38;5;222m░\x1b[38;5;223m \x1b[38;5;223m█\x1b[38;5;223m█\x1b[38;5;223m█\x1b[38;5;224m█\x1b[38;5;224m▓\x1b[38;5;224m▒\x1b[38;5;224m░\x1b[38;5;224m░\x1b[38;5;225m█\x1b[38;5;225m█\x1b[38;5;225m▓\x1b[38;5;225m \x1b[38;5;225m▒\x1b[38;5;226m█\x1b[38;5;226m█\x1b[38;5;226m▒\x1b[0m ║")
    p("║ \x1b[38;5;202m▒\x1b[38;5;202m \x1b[38;5;202m▒\x1b[38;5;203m▓\x1b[38;5;203m▒\x1b[38;5;203m \x1b[38;5;203m▒\x1b[38;5;203m \x1b[38;5;204m░\x1b[38;5;204m \x1b[38;5;204m▒\x1b[38;5;204m \x1b[38;5;204m░\x1b[38;5;205m░\x1b[38;5;205m▒\x1b[38;5;205m░\x1b[38;5;205m▒\x1b[38;5;206m░\x1b[38;5;206m \x1b[38;5;206m▒\x1b[38;5;206m▓\x1b[38;5;206m \x1b[38;5;207m░\x1b[38;5;207m▒\x1b[38;5;207m▓\x1b[38;5;207m░\x1b[38;5;207m░\x1b[38;5;208m▓\x1b[38;5;208m \x1b[38;5;208m \x1b[38;5;208m░\x1b[38;5;208m \x1b[38;5;209m▒\x1b[38;5;209m░\x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;210m░\x1b[38;5;210m \x1b[38;5;210m \x1b[38;5;210m░\x1b[38;5;210m▒\x1b[38;5;211m▓\x1b[38;5;211m▒\x1b[38;5;211m░\x1b[38;5;211m \x1b[38;5;212m░\x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m░\x1b[38;5;212m░\x1b[38;5;213m▓\x1b[38;5;213m \x1b[38;5;213m \x1b[38;5;213m░\x1b[38;5;213m \x1b[38;5;214m▒\x1b[38;5;214m░\x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;215m▒\x1b[38;5;215m \x1b[38;5;215m▒\x1b[38;5;215m \x1b[38;5;215m \x1b[38;5;216m▒\x1b[38;5;216m▓\x1b[38;5;216m▒\x1b[38;5;216m▒\x1b[38;5;216m░\x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m░\x1b[38;5;218m░\x1b[38;5;218m \x1b[38;5;218m▒\x1b[38;5;218m░\x1b[38;5;218m \x1b[38;5;219m░\x1b[38;5;219m░\x1b[38;5;219m \x1b[38;5;219m░\x1b[38;5;219m▒\x1b[38;5;220m \x1b[38;5;220m▒\x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;220m░\x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;221m▒\x1b[38;5;221m \x1b[38;5;221m░\x1b[38;5;222m░\x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m░\x1b[38;5;223m \x1b[38;5;223m▒\x1b[38;5;223m░\x1b[38;5;223m▒\x1b[38;5;224m░\x1b[38;5;224m▒\x1b[38;5;224m░\x1b[38;5;224m \x1b[38;5;224m░\x1b[38;5;225m \x1b[38;5;225m▒\x1b[38;5;225m▓\x1b[38;5;225m \x1b[38;5;225m░\x1b[38;5;226m▒\x1b[38;5;226m▓\x1b[38;5;226m░\x1b[0m ║")
    p("║ \x1b[38;5;202m░\x1b[38;5;202m \x1b[38;5;202m░\x1b[38;5;203m▒\x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;203m░\x1b[38;5;203m \x1b[38;5;204m░\x1b[38;5;204m \x1b[38;5;204m▒\x1b[38;5;204m \x1b[38;5;204m░\x1b[38;5;205m▒\x1b[38;5;205m░\x1b[38;5;205m \x1b[38;5;205m░\x1b[38;5;206m \x1b[38;5;206m \x1b[38;5;206m░\x1b[38;5;206m▒\x1b[38;5;206m \x1b[38;5;207m░\x1b[38;5;207m \x1b[38;5;207m▒\x1b[38;5;207m░\x1b[38;5;207m \x1b[38;5;208m▒\x1b[38;5;208m \x1b[38;5;208m░\x1b[38;5;208m░\x1b[38;5;208m \x1b[38;5;209m \x1b[38;5;209m░\x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;210m \x1b[38;5;210m \x1b[38;5;210m \x1b[38;5;210m░\x1b[38;5;210m░\x1b[38;5;211m▒\x1b[38;5;211m \x1b[38;5;211m░\x1b[38;5;211m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;213m▒\x1b[38;5;213m \x1b[38;5;213m░\x1b[38;5;213m░\x1b[38;5;213m \x1b[38;5;214m░\x1b[38;5;214m░\x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;215m░\x1b[38;5;215m \x1b[38;5;215m▒\x1b[38;5;215m░\x1b[38;5;215m \x1b[38;5;216m▒\x1b[38;5;216m \x1b[38;5;216m░\x1b[38;5;216m▒\x1b[38;5;216m░\x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;218m░\x1b[38;5;218m \x1b[38;5;218m░\x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;219m░\x1b[38;5;219m \x1b[38;5;219m \x1b[38;5;219m░\x1b[38;5;219m \x1b[38;5;220m \x1b[38;5;220m▒\x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;221m░\x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;223m \x1b[38;5;223m░\x1b[38;5;223m \x1b[38;5;223m▒\x1b[38;5;224m \x1b[38;5;224m▒\x1b[38;5;224m░\x1b[38;5;224m \x1b[38;5;224m \x1b[38;5;225m \x1b[38;5;225m░\x1b[38;5;225m▒\x1b[38;5;225m \x1b[38;5;225m░\x1b[38;5;226m \x1b[38;5;226m▒\x1b[38;5;226m░\x1b[0m ║")
    p("║ \x1b[38;5;202m░\x1b[38;5;202m \x1b[38;5;202m \x1b[38;5;203m░\x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;203m░\x1b[38;5;203m \x1b[38;5;204m \x1b[38;5;204m \x1b[38;5;204m░\x1b[38;5;204m \x1b[38;5;204m \x1b[38;5;205m░\x1b[38;5;205m░\x1b[38;5;205m \x1b[38;5;205m░\x1b[38;5;206m \x1b[38;5;206m \x1b[38;5;206m░\x1b[38;5;206m░\x1b[38;5;206m \x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;207m░\x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;208m▒\x1b[38;5;208m \x1b[38;5;208m░\x1b[38;5;208m░\x1b[38;5;208m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;210m░\x1b[38;5;210m \x1b[38;5;210m \x1b[38;5;210m \x1b[38;5;210m░\x1b[38;5;211m░\x1b[38;5;211m \x1b[38;5;211m \x1b[38;5;211m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;213m▒\x1b[38;5;213m \x1b[38;5;213m░\x1b[38;5;213m \x1b[38;5;213m \x1b[38;5;214m \x1b[38;5;214m░\x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;215m░\x1b[38;5;215m \x1b[38;5;215m░\x1b[38;5;215m \x1b[38;5;215m \x1b[38;5;216m░\x1b[38;5;216m \x1b[38;5;216m░\x1b[38;5;216m \x1b[38;5;216m░\x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;218m░\x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;219m \x1b[38;5;219m░\x1b[38;5;219m \x1b[38;5;219m \x1b[38;5;219m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;221m░\x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m░\x1b[38;5;223m \x1b[38;5;223m░\x1b[38;5;223m \x1b[38;5;223m░\x1b[38;5;224m \x1b[38;5;224m▒\x1b[38;5;224m \x1b[38;5;224m \x1b[38;5;224m \x1b[38;5;225m \x1b[38;5;225m░\x1b[38;5;225m░\x1b[38;5;225m \x1b[38;5;225m \x1b[38;5;226m \x1b[38;5;226m░\x1b[38;5;226m \x1b[0m ║")
    p("║ \x1b[38;5;202m \x1b[38;5;202m \x1b[38;5;202m \x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;203m░\x1b[38;5;203m \x1b[38;5;204m \x1b[38;5;204m \x1b[38;5;204m░\x1b[38;5;204m \x1b[38;5;204m \x1b[38;5;205m░\x1b[38;5;205m \x1b[38;5;205m \x1b[38;5;205m░\x1b[38;5;206m \x1b[38;5;206m \x1b[38;5;206m \x1b[38;5;206m░\x1b[38;5;206m \x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;208m░\x1b[38;5;208m \x1b[38;5;208m \x1b[38;5;208m \x1b[38;5;208m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;210m░\x1b[38;5;210m \x1b[38;5;210m \x1b[38;5;210m \x1b[38;5;210m \x1b[38;5;211m \x1b[38;5;211m \x1b[38;5;211m \x1b[38;5;211m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;213m░\x1b[38;5;213m \x1b[38;5;213m \x1b[38;5;213m \x1b[38;5;213m \x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;215m \x1b[38;5;215m \x1b[38;5;215m░\x1b[38;5;215m \x1b[38;5;215m \x1b[38;5;216m░\x1b[38;5;216m \x1b[38;5;216m \x1b[38;5;216m \x1b[38;5;216m░\x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;218m░\x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;219m░\x1b[38;5;219m░\x1b[38;5;219m \x1b[38;5;219m░\x1b[38;5;219m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;223m \x1b[38;5;223m \x1b[38;5;223m \x1b[38;5;223m░\x1b[38;5;224m \x1b[38;5;224m░\x1b[38;5;224m \x1b[38;5;224m \x1b[38;5;224m \x1b[38;5;225m \x1b[38;5;225m \x1b[38;5;225m░\x1b[38;5;225m \x1b[38;5;225m \x1b[38;5;226m \x1b[38;5;226m \x1b[38;5;226m \x1b[0m ║")
    p("║ \x1b[38;5;202m \x1b[38;5;202m \x1b[38;5;202m \x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;204m \x1b[38;5;204m \x1b[38;5;204m \x1b[38;5;204m \x1b[38;5;204m \x1b[38;5;205m \x1b[38;5;205m \x1b[38;5;205m \x1b[38;5;205m \x1b[38;5;206m \x1b[38;5;206m \x1b[38;5;206m \x1b[38;5;206m \x1b[38;5;206m \x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;208m \x1b[38;5;208m \x1b[38;5;208m \x1b[38;5;208m \x1b[38;5;208m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;210m \x1b[38;5;210m \x1b[38;5;210m \x1b[38;5;210m \x1b[38;5;210m \x1b[38;5;211m \x1b[38;5;211m \x1b[38;5;211m \x1b[38;5;211m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;213m \x1b[38;5;213m \x1b[38;5;213m \x1b[38;5;213m \x1b[38;5;213m \x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;215m \x1b[38;5;215m \x1b[38;5;215m \x1b[38;5;215m \x1b[38;5;215m \x1b[38;5;216m \x1b[38;5;216m \x1b[38;5;216m \x1b[38;5;216m \x1b[38;5;216m \x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;219m \x1b[38;5;219m░\x1b[38;5;219m \x1b[38;5;219m \x1b[38;5;219m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;223m \x1b[38;5;223m \x1b[38;5;223m \x1b[38;5;223m \x1b[38;5;224m \x1b[38;5;224m \x1b[38;5;224m \x1b[38;5;224m \x1b[38;5;224m \x1b[38;5;225m \x1b[38;5;225m \x1b[38;5;225m \x1b[38;5;225m \x1b[38;5;225m \x1b[38;5;226m \x1b[38;5;226m \x1b[38;5;226m \x1b[0m ║")
    p("║ \x1b[38;5;202m \x1b[38;5;202m \x1b[38;5;202m \x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;203m \x1b[38;5;204m \x1b[38;5;204m \x1b[38;5;204m \x1b[38;5;204m \x1b[38;5;204m \x1b[38;5;205m \x1b[38;5;205m \x1b[38;5;205m \x1b[38;5;205m \x1b[38;5;206m \x1b[38;5;206m \x1b[38;5;206m \x1b[38;5;206m \x1b[38;5;206m \x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;207m \x1b[38;5;208m \x1b[38;5;208m \x1b[38;5;208m \x1b[38;5;208m \x1b[38;5;208m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;209m \x1b[38;5;210m \x1b[38;5;210m \x1b[38;5;210m \x1b[38;5;210m \x1b[38;5;210m \x1b[38;5;211m \x1b[38;5;211m \x1b[38;5;211m \x1b[38;5;211m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;212m \x1b[38;5;213m \x1b[38;5;213m \x1b[38;5;213m \x1b[38;5;213m \x1b[38;5;213m \x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;214m \x1b[38;5;215m \x1b[38;5;215m \x1b[38;5;215m \x1b[38;5;215m \x1b[38;5;215m \x1b[38;5;216m \x1b[38;5;216m \x1b[38;5;216m \x1b[38;5;216m \x1b[38;5;216m \x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;217m \x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;218m \x1b[38;5;219m \x1b[38;5;219m \x1b[38;5;219m \x1b[38;5;219m \x1b[38;5;219m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;220m \x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;221m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;222m \x1b[38;5;223m \x1b[38;5;223m \x1b[38;5;223m \x1b[38;5;223m \x1b[38;5;224m \x1b[38;5;224m \x1b[38;5;224m \x1b[38;5;224m \x1b[38;5;224m \x1b[38;5;225m \x1b[38;5;225m \x1b[38;5;225m \x1b[38;5;225m \x1b[38;5;225m \x1b[38;5;226m \x1b[38;5;226m \x1b[38;5;226m \x1b[0m ║")
    p(f"║ \x1b[38;5;202mRelease      : {__version__:<102s}\x1b[0m ║")
    p(f"║ \x1b[38;5;206mGroup        : SecurityShrimp{' ' * 88}\x1b[0m ║")
    p(f"║ \x1b[38;5;210mURL          : https://github.com/f8al/shrimpinjector{' ' * 64}\x1b[0m ║")
    p(f"║ \x1b[38;5;214mGreets       : w00w00{' ' * 96}\x1b[0m ║")
    p("╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝")
    p("\x1b[0m")


def list_payloads():
    print_banner()
    print("Available payload types:", file=sys.stderr)
    print(file=sys.stderr)
    for name, desc in PAYLOAD_DESCRIPTIONS.items():
        print(f"  {name:<14} {desc}", file=sys.stderr)
    print(file=sys.stderr)
    print("Usage: shrimpinjector <type> <input> [options] [-- assembly_args...]", file=sys.stderr)


def _add_common_args(parser):
    parser.add_argument(
        "-e", "--encryption", choices=["aes", "xor"], default="aes",
        help="Encryption: aes (AES-256-CBC, default) or xor",
    )
    parser.add_argument("--key", help="Encryption key as hex")
    parser.add_argument("--iv", help="AES IV as hex (16 bytes)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--template", help="Custom template file")


def _add_keying_args(parser):
    parser.add_argument(
        "--keying",
        help="Environmental keying: name=value,name=value "
             "(hostname, domain, user, machineguid)",
    )


def _add_type_method_args(parser):
    parser.add_argument("--type", help="Fully qualified type name (e.g. Namespace.Class)")
    parser.add_argument("--method", help="Method name to invoke on --type")


def _add_compile_arg(parser):
    parser.add_argument(
        "--compile", action="store_true",
        help="Auto-compile with Mono mcs after generation",
    )


def build_parser():
    parser = argparse.ArgumentParser(
        prog="shrimpinjector",
        description="ShrimpInjector — Unified .NET assembly & shellcode payload builder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-V", "--version", action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="payload_type", help="Payload type")

    # --- list ---
    subparsers.add_parser("list", help="List available payload types")

    # --- msbuild ---
    p = subparsers.add_parser("msbuild", help=PAYLOAD_DESCRIPTIONS["msbuild"])
    p.add_argument("assembly", nargs="?", help=".NET assembly (.exe or .dll)")
    _add_common_args(p)
    _add_keying_args(p)
    _add_type_method_args(p)
    p.add_argument(
        "--staged", help="Staged delivery URL — generates dropper + .bin",
    )
    p.add_argument(
        "--listener",
        help="Build named pipe listener: pipe=<name>",
    )

    # --- installutil ---
    p = subparsers.add_parser("installutil", help=PAYLOAD_DESCRIPTIONS["installutil"])
    p.add_argument("assembly", help=".NET assembly")
    _add_common_args(p)
    _add_keying_args(p)
    _add_type_method_args(p)
    _add_compile_arg(p)

    # --- workflow ---
    p = subparsers.add_parser("workflow", help=PAYLOAD_DESCRIPTIONS["workflow"])
    p.add_argument("assembly", help=".NET assembly")
    _add_common_args(p)
    _add_keying_args(p)
    _add_type_method_args(p)
    # workflow uses -o as output directory
    p._option_string_actions["-o"].help = "Output directory (default: output/)"

    # --- regasm ---
    p = subparsers.add_parser("regasm", help=PAYLOAD_DESCRIPTIONS["regasm"])
    p.add_argument("assembly", help=".NET assembly")
    _add_common_args(p)
    _add_keying_args(p)
    _add_type_method_args(p)
    _add_compile_arg(p)

    # --- regsvcs ---
    p = subparsers.add_parser("regsvcs", help=PAYLOAD_DESCRIPTIONS["regsvcs"])
    p.add_argument("assembly", help=".NET assembly")
    _add_common_args(p)
    _add_keying_args(p)
    _add_type_method_args(p)
    _add_compile_arg(p)
    p.add_argument("--keyfile", help="Existing .snk keypair file for strong naming")

    # --- csc ---
    p = subparsers.add_parser("csc", help=PAYLOAD_DESCRIPTIONS["csc"])
    p.add_argument("assembly", help=".NET assembly")
    _add_common_args(p)
    _add_keying_args(p)
    _add_type_method_args(p)
    _add_compile_arg(p)

    # --- powershell ---
    p = subparsers.add_parser("powershell", help=PAYLOAD_DESCRIPTIONS["powershell"])
    p.add_argument("assembly", help=".NET assembly")
    _add_common_args(p)
    _add_keying_args(p)

    # --- vbscript ---
    p = subparsers.add_parser("vbscript", help=PAYLOAD_DESCRIPTIONS["vbscript"])
    p.add_argument("assembly", help=".NET assembly")
    _add_common_args(p)

    # --- hta ---
    p = subparsers.add_parser("hta", help=PAYLOAD_DESCRIPTIONS["hta"])
    p.add_argument("assembly", help=".NET assembly")
    _add_common_args(p)

    # --- vba ---
    p = subparsers.add_parser("vba", help=PAYLOAD_DESCRIPTIONS["vba"])
    p.add_argument("assembly", help=".NET assembly")
    _add_common_args(p)

    # --- shellcode ---
    p = subparsers.add_parser("shellcode", help=PAYLOAD_DESCRIPTIONS["shellcode"])
    p.add_argument("shellcode", help="Raw shellcode file (.bin)")
    p.add_argument("-x", "--xor", action="store_true", help="Apply XOR encryption")
    p.add_argument("--xor-key", help="XOR key as hex (default: random 16 bytes)")
    p.add_argument("--no-wait", action="store_true", help="Don't wait for thread (donut -x 3)")
    p.add_argument("-o", "--output", help="Output .bas file")
    p.add_argument("--template", help="Custom template file")

    return parser


def main():
    argv = sys.argv[1:]
    assembly_args = []
    if "--" in argv:
        split_idx = argv.index("--")
        assembly_args = argv[split_idx + 1:]
        argv = argv[:split_idx]

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.payload_type:
        print_banner()
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.payload_type == "list":
        list_payloads()
        sys.exit(0)

    print_banner()

    builder = PAYLOAD_BUILDERS.get(args.payload_type)
    if not builder:
        print(f"[-] Unknown payload type: {args.payload_type}", file=sys.stderr)
        print(f"    Run 'shrimpinjector list' for available types.", file=sys.stderr)
        sys.exit(1)

    if args.payload_type == "msbuild" and not args.assembly and not args.listener:
        parser.parse_args([args.payload_type, "--help"])

    builder(args, assembly_args)


if __name__ == "__main__":
    main()

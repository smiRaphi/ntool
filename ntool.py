#!/usr/bin/python3
import argparse
import logging
from utils import *

def setup_logging(debug=False):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format="%(message)s")

def cmd_basic(args):
    args.func(args.input, args.out or "")

def cmd_devflag(args):
    args.func(args.input, 1 if args.dev else 0)

def cmd_cci2cia(args):
    cci2cia(
        args.input,
        args.out or "",
        1 if args.cci_dev else 0,
        1 if args.cia_dev else 0
    )

def cmd_cdn2cia(args):
    cdn2cia(
        args.input,
        args.out or "",
        args.title_ver or "",
        1 if args.cdn_dev else 0,
        1 if args.cia_dev else 0
    )

def cmd_cia2cdn(args):
    cia2cdn(
        args.input,
        args.out or "",
        args.titlekey or "",
        1 if args.cia_dev else 0
    )

def create_parser():
    parser = argparse.ArgumentParser(
        description="Nintendo 3DS toolkit for CIA/CCI/NCCH manipulation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Examples:\n"
                "  python3 ntool.py <command> --help\n"
                "  python3 ntool.py srl_retail2dev --out dev_game.srl game.srl \n"
                "  python3 ntool.py cia_dev2retail --out retail_game.cia game.cia\n"
                "  python3 ntool.py cia_retail2dev --out dev_game.cia game.cia\n"
                "  python3 ntool.py cci_dev2retail --out retail_game.cci game.cci\n"
                "  python3 ntool.py cci_retail2dev --out dev_game.cci game.cci\n"
                "  python3 ntool.py csu2retailcias --out .\\extracted update.csu\n"
                "  python3 ntool.py ncch_extractall --dev game.ncch\n"
                "  python3 ntool.py ncch_rebuildall .\\extracted_ncch --dev\n"
                "  python3 ntool.py cia_extractall game.cia --dev\n"
                "  python3 ntool.py cia_rebuildall .\\extracted_cia --dev\n"
                "  python3 ntool.py cci_extractall game.cci --dev\n"
                "  python3 ntool.py cci_rebuildall .\\extracted_cci --dev\n"
                "  python3 ntool.py cci2cia --out game.cia --cci-dev --cia-dev game.cci\n"
                "  python3 ntool.py cdn2cia --out game.cia --title-ver 16 --cdn-dev --cia-dev .\\path\\to\\tmd\n"
                "  python3 ntool.py cia2cdn --out game.cdn --titlekey ABCDEF1234567890ABCDEF1234567890 --cia-dev game.cia\n")
    )

    parser.add_argument("--debug", action="store_true",
                        help="Enable debug output")

    sub = parser.add_subparsers(dest="command", help='Available commands')

    basic_cmds = [
        ["srl_retail2dev", "Convert SRL retail to dev format"],
        ["cia_dev2retail", "Convert CIA dev to retail format"],
        ["cia_retail2dev", "Convert CIA retail to dev format"],
        ["cci_dev2retail", "Convert CCI dev to retail format"],
        ["cci_retail2dev", "Convert CCI retail to dev format"],
        ["csu2retailcias", "Extract retail CIAs from CSU"],
    ]

    for name, help_text in basic_cmds:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("input")
        p.add_argument("--out", help="Output folder")
        p.set_defaults(func=globals()[name], runner=cmd_basic)

    for fmt in ["ncch", "cia", "cci"]:
        for action in ["extractall", "rebuildall"]:
            name = f"{fmt}_{action}"
            p = sub.add_parser(name, help=f"{action.capitalize()} all files in {fmt.upper()} format")
            p.add_argument("input")
            p.add_argument("--dev", action="store_true", help="Used to pass dev crypto")
            p.set_defaults(func=globals()[name], runner=cmd_devflag)
            p.epilog = ("Note: The order of operations is extractall, modify the exefs.bin, romfs.bin, or .ncch files directly, followed by rebuildall.\n")

    p = sub.add_parser("cci2cia", help="Convert CCI to CIA")
    p.add_argument("input")
    p.add_argument("--out", help="Output folder")
    p.add_argument("--cci-dev", action="store_true", help="Use if CCI is dev-crypted/signed")
    p.add_argument("--cia-dev", action="store_true", help="Use to build a dev-signed CIA")
    p.set_defaults(runner=cmd_cci2cia)

    p = sub.add_parser("cdn2cia", help="Convert CDN to CIA")
    p.add_argument("input", help="Location of CDN folder with TMD and content files")
    p.add_argument("--out", help="Output file or folder (default: parent directory of input)")
    p.add_argument("--title-ver", help="Title version (default: newest version in TMD)")
    p.add_argument("--cdn-dev", action="store_true", help="Use if the CDN records are dev-signed/crypted")
    p.add_argument("--cia-dev", action="store_true", help="Use to build a dev-signed CIA")
    p.set_defaults(runner=cmd_cdn2cia)

    p = sub.add_parser("cia2cdn", help="Convert CIA to CDN")
    p.add_argument("input")
    p.add_argument("--out", help="Output folder")
    p.add_argument("--titlekey", help="Used with a custom title key if the CIA doesn't have a signed ticket")
    p.add_argument("--cia-dev", action="store_true", help="Use if the CIA is Dev-signed")
    p.set_defaults(runner=cmd_cia2cdn)

    return parser

def main(args=None):
    parser = create_parser()
    args = parser.parse_args(args)

    setup_logging(args.debug)

    if not hasattr(args, "runner"):
        parser.print_help()
        return

    args.runner(args)

if __name__ == "__main__":
    main()
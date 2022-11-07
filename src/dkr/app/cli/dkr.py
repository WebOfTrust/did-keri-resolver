# -*- encoding: utf-8 -*-
"""
kara.app.commands module

"""
import multicommand
import logging

from dkr.app.cli import commands
from keri import help


help.ogler.level = logging.CRITICAL
help.ogler.reopen(name="dkr", temp=True, clear=True)


def main():
    parser = multicommand.create_parser(commands)
    args = parser.parse_args()

    try:
        args.handler(args)
    except Exception as ex:
        print(f"ERR: {ex}")
        return -1
        # raise ex


if __name__ == "__main__":
    main()

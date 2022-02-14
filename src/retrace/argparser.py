# Copyright (C) 2012 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import argparse
import logging
import sys

from io import StringIO


class ArgumentParser(argparse.ArgumentParser):
    def __init__(self, description=None, prog=sys.argv[0], usage=None,
                 add_help=True, argument_default=None, prefix_chars="-"):
        super().__init__(epilog="See 'man %(prog)s' for more information.",
                         description=description,
                         prog=prog,
                         usage=usage,
                         add_help=add_help,
                         argument_default=argument_default,
                         prefix_chars=prefix_chars)
        self.add_argument("-v", "--verbose", action="store_true", default=False, dest="verbose")

    def parse_args(self, args=None, namespace=None):
        args = super().parse_args(args=args, namespace=namespace)
        if args.verbose:
            level = logging.DEBUG
        else:
            level = logging.INFO

        # pylint: disable=protected-access
        if args.foreground:
            args._log = None
            logging.basicConfig(level=level)
        else:
            args._log = StringIO()
            logging.basicConfig(level=level, stream=args._log)

        return args

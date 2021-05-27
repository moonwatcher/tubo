# -*- coding: utf-8 -*-

import os
import logging
from error import *
from argparse import ArgumentParser

class CommandLineParser(object):
    def __init__(self, node):
        self.node = node
        self.parser = ArgumentParser(**self.node['instruction'])
        self.load()

    @property
    def sectioned(self):
        return 'section' in self.node and 'action' in self.node['section'] and self.node['section']['action']

    def load(self):
        def add_argument(parser, name):
            node = self.node['prototype'][name]
            parser.add_argument(*node['flag'], **node['parameter'])

        # evaluate the type for each prototype
        for argument in self.node['prototype'].values():
            if 'type' in argument['parameter']:
                argument['parameter']['type'] = eval(argument['parameter']['type'])

        # add global arguments
        for argument in self.node['global']['argument']:
            add_argument(self.parser, argument)

        if self.sectioned:
            # Add individual command sections
            sub = self.parser.add_subparsers(**self.node['section']['instruction'])
            for action in self.node['section']['action']:
                action_parser = sub.add_parser(**action['instruction'])
                if 'argument' in action:
                    for argument in action['argument']:
                        add_argument(action_parser, argument)

                # Add groups of arguments, if any.
                if 'group' in action:
                    for group in action['group']:
                        group_parser = action_parser.add_argument_group(**group['instruction'])
                        if 'argument' in group:
                            for argument in group['argument']:
                                add_argument(group_parser, argument)

    def parse(self):
        instruction = {}
        arguments = vars(self.parser.parse_args())
        for k,v in arguments.items():
            if k is not None and v is not None:
                instruction[k] = v

        if self.sectioned and 'action' not in instruction:
            self.parser.print_help()
            raise HelpInvokedException()
        else:
            if 'scan path' in instruction and instruction['scan path']:
                for index, path in enumerate(instruction['scan path']):
                    instruction['scan path'][index] = os.path.abspath(os.path.expanduser(os.path.expandvars(path)))
            return instruction

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import sys

from interface import CommandLineParser
from environment import Environment
from rest import RestResolver
from queue import Queue
from ontology import Ontology
from error import *

class Tubo(object):
    def __init__(self, ontology=None):
        self.env = None
        self.ontology = {
            'parse command line': False,
            'demonized': False,
            'interactive': True,
            'blocking': True,
            'start rest api': True,
            'interface': None,
            'submit': False
        }

        if ontology is not None:
            self.ontology.update(ontology)

        self.start()

    @property
    def queue(self):
        return self.env.queue

    @property
    def rest(self):
        return self.env.rest

    def start(self):
        try:
            self.env = Environment()
            if self.ontology['parse command line']:
                if self.ontology['interface'] is None:
                    self.ontology['interface'] = self.env.system['interface']

                interface = self.env.configuration.state['interface'][self.ontology['interface']]
                try:
                    self.ontology.update(CommandLineParser(interface).parse())
                except HelpInvokedException:
                    pass
                else:
                    self.env.ignite(self.ontology)
                    self.env.queue = Queue(self.env)

                    if self.ontology['start rest api']:
                        self.env.rest = RestResolver(self.env, self.queue)
                        self.rest.ignite()

                    if self.ontology['demonized']:
                        self.queue.ignite()
                    else:
                        if self.ontology['submit']:
                            self.queue.submit(self.ontology)
                        else:
                            self.queue.push(self.ontology)
                            self.queue.ignite()

        except (KeyboardInterrupt, SystemExit):
            self.kill()
            sys.exit(0)

        except TuboError as e:
            logging.getLogger('Environment').critical(e)
            self.kill()
            sys.exit(1)

    def stop(self, kill=False):
        if self.queue is not None:
            if kill: self.queue.stop()
            self.queue.wait()
            self.env.queue = None

        if self.rest is not None:
            self.rest.close()
            self.env.rest = None

        if self.env is not None:
            self.env.close()
            self.env = None

    def kill(self):
        self.stop(True)

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s.%(levelname)s: %(message)s', datefmt='%a %b %d %H:%M:%S %Y')
    tubo = Tubo(
        {
            'parse command line': True,
            'start rest api': False,
            'interactive': False,
            'blocking': False
        }
    )
    tubo.stop()
    sys.exit(0)

if __name__ == '__main__':
    main()

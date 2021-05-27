#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging

from tubo import Tubo

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s.%(levelname)s: %(message)s', datefmt='%a %b %d %H:%M:%S %Y')
    tubo = Tubo(
        {
            'parse command line': True,
            'start rest api': True,
            'interface': 'daemon',
            'interactive': True,
            'demonized': True,
            'blocking': True
        }
    )
    tubo.stop()
    sys.exit(0)

if __name__ == '__main__':
    main()

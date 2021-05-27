#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify, abort, render_template, url_for
from flask.json import JSONEncoder
from flask.views import View
from bson.objectid import ObjectId
from datetime import datetime
from urllib.request import Request, urlopen

import threading
import logging
import sys

HOST = '0.0.0.0'

class OntologyJSONEncoder(JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, set):
            return list(o)
        return JSONEncoder.default(self, o)

class RestResolver(object):
    def __init__(self, env, queue=None):
        self.log = logging.getLogger('Rest')
        self.env = env
        self.queue = queue
        self.thread = None

        self.application = Flask(__name__)
        self.application.json_encoder = OntologyJSONEncoder

        if self.queue is not None:
            self.application.add_url_rule('/queue', view_func=self.resolve_queue, methods=['GET', 'POST'])

        self.application.add_url_rule('/conf/<path:section>', view_func=self.resolve_configuration, methods=['GET', 'POST'])
        self.application.add_url_rule('/shutdown', view_func=self.resolve_shutdown, methods=['GET', 'POST'])

        # self.application.add_url_rule('/web/', view_func=self.resolve_web_home, methods=['GET', 'POST'])
        self.application.add_url_rule('/web/<path:uri>', view_func=self.resolve_web_view, methods=['GET', 'POST'])
        # self.application.add_url_rule('/chart/<path:uri>', view_func=self.resolve_chart, methods=['GET', 'POST'])

        self.application.add_url_rule('/<path:uri>', view_func=self.resolve_uri, methods=['GET', 'POST'])
        self.application.add_url_rule('/', view_func=self.resolve_home, methods=['GET', 'POST'])

        # set logging level for werkzeug to ERROR  
        logging.getLogger('werkzeug').setLevel(logging.ERROR)

    def close(self):
        request = Request('http://localhost:5000/shutdown')
        response = urlopen(request)

    def run(self):
        self.application.run(host=HOST, port=self.env.system['api port'])

    def ignite(self):
        try:
            self.log.debug('starting REST api')
            self.thread = threading.Thread(target=self.run, name='rest api')
            self.thread.start()

        except(KeyboardInterrupt, SystemExit) as e:
            self.log.debug('REST received kill')
            sys.exit(0)

    def resolve_uri(self, uri):
        result = None
        absolute = '/{}'.format(uri)
        document = self.env.resolver.resolve(absolute, None, None)

        if document:
            result = jsonify(document)
            result.headers['Access-Control-Allow-Origin'] = '*'
        else:
            document = self.env.resolver.browse(uri)
            if document:
                result = jsonify(document)
                result.headers['Access-Control-Allow-Origin'] = '*'
            else : abort(404)

        return result

    def resolve_home(self):
        result = jsonify(self.env.system)
        result.headers['Access-Control-Allow-Origin'] = '*'
        return result

    def resolve_web_home(self):
        return render_template('index.html', tables=self.env.table, url=request.url[:-len(request.path)+1])

    def resolve_web_view(self, uri):
        document = self.env.resolver.resolve('/{}'.format(uri), None, None)
        context = {
            'uri': uri,
            'base': request.url[:-len(request.path)+1],
        }
        return render_template('index.html', context=context, document=document)

    def resolve_chart(self, uri):
        result = None
        if uri.startswith("m/resource/"):
            document = self.env.resolver.resolve('/{}'.format(uri), None, None)
            if document:  
                numbers = document['body']['lane']['cycle quality report']['cycle quality distribution']
                numbers = [list(e) for e in zip(numbers['cycle quality min'],numbers['cycle quality first quartile'],numbers['cycle quality median'],numbers['cycle quality third quartile'],numbers['cycle quality max'])]
                result = jsonify({'numbers':numbers})
                result.headers['Access-Control-Allow-Origin'] = '*'
                return result
        abort(404)

    def resolve_shutdown(self):
        self.shutdown()
        return 'shutting down'

    def resolve_queue(self):
        result = jsonify(self.queue.ontology)
        result.headers['Access-Control-Allow-Origin'] = '*'
        return result

    def resolve_configuration(self, section):
        result = None
        if section in self.env.configuration.state:
            result = jsonify(self.env.configuration.state[section])
            result.headers['Access-Control-Allow-Origin'] = '*'
        else: abort(404)
        return result

    def shutdown(self):
        halt = request.environ.get('werkzeug.server.shutdown')
        if halt is None:
            self.log.error('Not running with the Werkzeug server')
        self.log.debug('REST api is shutting down')
        halt()

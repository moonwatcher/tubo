# -*- coding: utf-8 -*-

import os

class HelpInvokedException(Exception):
    def __init__(self):
        super(Exception, self)

class TuboError(Exception):
    def __init__(self):
        super(Exception, self)

class InconsistencyError(TuboError):
    def __init__(self, message):
        super(TuboError, self).__init__(message)

class JSONParseError(TuboError):
    def __init__(self, error):
        super(TuboError, self).__init__(str(error))

class NoOverwriteError(TuboError):
    def __init__(self, path):
        super(TuboError, self).__init__('refusing to overwrite {}'.format(path))
        self.path = path

class ConfigurationError(TuboError):
    def __init__(self, message):
        super(TuboError, self).__init__(message)

class UmidValidationError(TuboError):
    def __init__(self, message):
        super(TuboError, self).__init__(message)

class UnresolvableResourceError(TuboError):
    def __init__(self, message):
        super(TuboError, self).__init__(message)

class ValidationError(TuboError):
    def __init__(self, message):
        super(TuboError, self).__init__(message)

class NetworkError(TuboError):
    def __init__(self, message):
        super(TuboError, self).__init__(message)

class InvalidOntologyError(TuboError):
    def __init__(self, message):
        super(TuboError, self).__init__(message)

class PermissionDeniedError(TuboError):
    def __init__(self, path):
        super(TuboError, self).__init__('permission denied for {}'.format(path))
        self.path = path

class FileNotFoundError(TuboError):
    def __init__(self, path):
        super(TuboError, self).__init__('file {} does not exist'.format(path))
        self.path = path

class InvalidResourceError(TuboError):
    def __init__(self, message):
        super(TuboError, self).__init__(message)

class UnsuccessfulTerminationError(TuboError):
    def __init__(self, message):
        super(TuboError, self).__init__(message)

__author__ = 'milk'

from datetime import datetime

def ISOtoStr(ISODate):
    return datetime.strptime( ISODate, "%Y-%m-%dT%H:%M:%S")

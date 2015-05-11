# *-* coding: utf-8 *-*
__author__ = 'milk'

from pymongo import MongoClient

mongo = MongoClient()

class User():
    def __init__(self):
        pass


class Item():
    def __init__(self):
        self.collection = mongo['clothes']['items']

    def get_all(self):
        return self.collection.find()

    def get_one(self, iid):
        return self.collection.find_one({'_id': iid})
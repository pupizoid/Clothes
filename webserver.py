# *-* coding: utf-8 *-*

import re
import time
import os
import json
import logging
import urlparse
import urllib
import tornado.httpserver
import tornado.httputil
import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.options
import tornado.auth
import tornado.escape
import datetime
import mailing
import Image
import StringIO

from bson import ObjectId
from uuid import uuid4
from urllib import urlencode
from pprint import pprint
from pymongo.errors import DuplicateKeyError
from pymongo import MongoClient
from passlib.utils import generate_password
from passlib.hash import sha256_crypt
from tornado.template import Loader
from datetime import datetime
from torndsession.sessionhandler import SessionBaseHandler


DB_NAME = 'clothes'
IMAGE_DIR = os.path.abspath(os.path.dirname(__file__)) + '/static/images/items/'


class CustomException(Exception):
    def __init__(self, *args, **kwargs):
        self.message = args
        self.kwargs = kwargs

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        try:
            s = " ".join(self.message)
            s += " {" + " ".join("%s: %s," % (str(k), str(v)) for k, v in self.kwargs.items()).strip(',') + "}"
        except Exception, e:
            s = "-----" + str(type(e)) + str(e)
        return s


class PermissionsCollectionError(CustomException):
    pass


def authenticated(method, permission='public'):
    """
        Decorate methods with this to require that the user be logged in and checks it access_level.

        Access levels are stored in mongodb collection 'permissions'

        :sets self.user_access_level (String)
    """

    @tornado.web.functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if not self.current_user:
            if self.request.method in ("GET", "HEAD", "POST"):
                url = self.get_login_url()
                if "?" not in url:
                    if urlparse.urlsplit(url).scheme:
                        # if login url is absolute, make next absolute too
                        next_url = self.request.full_url()
                    else:
                        next_url = self.request.uri
                    url += "?" + urlencode(dict(next=next_url))
                self.redirect(url)
                return
            raise tornado.web.HTTPError(403)
        else:
            db = application.mongo[DB_NAME]
            permissions = db.permissions.find_one({'_id': permission})
            if not permissions:
                raise PermissionsCollectionError('Permissions collection doesn\'t exists or empty', db=DB_NAME)
            try:
                user_role = db.users.find_one({'login': self.get_current_user()})['role']
            except TypeError:
                # if user doesn't have role we permit him public access
                user_role = 'public'
            if user_role in permissions['deny']:
                raise tornado.web.HTTPError(403)
            elif user_role in permissions['allow']:
                self.user_permission = user_role
                return method(self, *args, **kwargs)
            else:
                raise tornado.web.HTTPError(417)

    return wrapper


class Data():
    """ Data unit for handlers """

    def __init__(self):
        self.db = application.mongo[DB_NAME]

    def __getattr__(self, item):
        """ Links attribute to database collections """
        return self.db.__getattr__(item)

    @staticmethod
    def ISOtoStr(ISODate):
        try:
            return datetime.strftime(ISODate, "%Y-%m-%d %H:%M:%S")
        except KeyboardInterrupt:
            return 'Отсутсвует'

    @staticmethod
    def purge(dir, pattern):
        for f in os.listdir(dir):
            if re.search(pattern, f):
                os.remove(os.path.join(dir, f))

class BaseHandler(SessionBaseHandler):
    def __init__(self, *args, **kwargs):
        super(SessionBaseHandler, self).__init__(*args, **kwargs)

    def get_current_user(self):
        return self.get_secure_cookie('user')

    def get_cart_html(self):
        data = Data()
        html = ''
        cart = data.db.cart.find_one(dict(_id=self.session.id))
        loader = Loader(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'templates'))
        try:
            items = {r['_id']: r for r in
                     data.db.items.find({'_id': {'$in': map(lambda x: ObjectId(x), cart['iids'])}})}
        except TypeError:
            items = {}
        html += loader.load('cart.html').generate(
            items=items.values(),
            total_price=reduce(lambda res, x: res + int(x['price']), items.values(), 0)
        )
        return html

    def get_leader_html(self):
        data = Data()
        leader = data.db.items.find_one(dict(leader={'$exists': True}))
        loader = Loader(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'templates'))
        try:
            return loader.load('item.html').generate(
                id=leader.get('_id', ''),
                name=leader.get('name', ''),
                comment=leader.get('comment', ''),
                price=leader.get('price', ''),
                leader=True
            )
        except TypeError:
            return ''

    @property
    def cart_count(self):
        data = Data()
        try:
            return len(data.db.cart.find_one(dict(_id=self.session.id)).get('iids', {}))
        except (TypeError, KeyError, AttributeError):
            return False

    @property
    def dict_args(self):
        return {k: v[0] if len(v) == 1 else v for k, v in self.request.arguments.items()}


###############
# User entity #
###############

class Register(BaseHandler):
    def get(self, *args, **kwargs):
        data = Data()
        data.title = "Регистрация"
        self.render('register.html', data=data)

    def post(self, *args, **kwargs):
        email = self.get_argument('email', None)
        if email:
            data = Data()
            pwd = generate_password(10)
            user = dict(
                email=email,
                pwd=sha256_crypt.encrypt(pwd),
                role='public'
            )
            try:
                data.db.users.insert(user)
            except DuplicateKeyError:
                raise tornado.web.HTTPError(500)
            if mailing.send_register_mail(user, pwd):
                self.finish()
            else:
                raise tornado.web.HTTPError(501)
        else:
            raise tornado.web.HTTPError(500)


class Login(BaseHandler):
    def get(self, *args, **kwargs):
        data = Data()
        data.title = 'Вход'
        self.render('login.html', data=data)

    def post(self, *args, **kwargs):
        data = Data()
        if 'email' in self.dict_args.keys():
            user = data.users.find_one({'email': self.dict_args['email']})
            if sha256_crypt.verify(self.dict_args['pwd'], user['pwd']):
                try:
                    self.set_secure_cookie('user', self.dict_args['email'], expires_days=int(self.dict_args['expires']))
                except KeyError:
                    self.set_secure_cookie('user', self.dict_args['email'], expires_days=1)
                self.redirect('/admin')
            else:
                self.clear_cookie('user')
                self.write(dict(code=401))
                self.finish()
        else:
            self.clear_cookie('user')
            self.write(dict(code=402))
            self.finish()


class Logout(BaseHandler):
    """ Yet another logout handler """
    def get(self, *args, **kwargs):
        self.clear_cookie('user')


class Profile(BaseHandler):
    # @authenticated
    def get(self, *args, **kwargs):
        data = Data()
        data.title = 'Профиль'
        self.render('profile.html', data=data)

    # @authenticated(permission='admin')
    def post(self, *args, **kwargs):
        data = Data()
        print self.request.dict_args
        data.users.update({'email': self.get_current_user()}, {'$set': self.dict_args}, True)


class Main(BaseHandler):
    def get(self, *args, **kwargs):
        data = Data()
        data.items = ''
        data.cart = ''
        loader = Loader(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'templates'))
        items = data.db.items.find()
        data.cart_html = self.get_cart_html()
        data.cart_count = data.db.cart.find(dict(_id=self.session.id)).count()
        data.leader = self.get_leader_html()
        for item in items:
            data.items += loader.load('item.html').generate(
                id=item.get('_id', ''),
                name=item.get('name', ''),
                comment=item.get('comment', ''),
                price=item.get('price', ''),
                leader=False
            )
        self.render('main.html', data=data)


class AddItemToCart(BaseHandler):
    def post(self, iid):
        iid = iid if iid else None
        if iid:
            data = Data()
            try:
                data.db.cart.insert(dict(
                    _id=self.session.id,
                    created=datetime.utcnow(),
                    iids=[iid]
                ))
            except DuplicateKeyError:
                data.db.cart.update(dict(_id=self.session.id),
                                    {'$addToSet': dict(iids=iid)})
            self.finish()
        else:
            raise tornado.web.HTTPError(404)


class DelItemFromCart(BaseHandler):
    def get(self, iid):
        iid = iid if iid else None
        if iid:
            data = Data()
            res = data.db.cart.update_one(dict(_id=self.session.id), {'$pop': {'iids': iid}})
            if res.matched_count:
                self.finish()
            else:
                raise tornado.web.HTTPError(404)
        else:
            raise tornado.web.HTTPError(404)


class GetCartHTML(BaseHandler):
    def get(self):
        self.write({'html': self.get_cart_html()})


class Payment(BaseHandler):
    def get(self, oid):
        pass


class Detail(BaseHandler):
    def get(self, iid):
        data = Data()
        data.item = data.db.items.find_one(dict(_id=ObjectId(iid)))
        data.cart = self.get_cart_html()
        data.order_settings = {}
        self.render('detail.html', data=data)


class Checkout(BaseHandler):
    def get(self):
        data = Data()
        cart = data.db.cart.find_one(dict(_id=self.session.id))
        try:
            items = {r['_id']: r for r in
                     data.db.items.find({'_id': {'$in': map(lambda x: ObjectId(x), cart['iids'])}})}
        except TypeError:
            items = {}
        data.cart = items.values()
        data.sizes = ['M', 'S', 'L']
        data.colors = ['Черный', 'Белый']
        data.shipping = 300
        data.leader = self.get_leader_html()
        pprint(data.cart_count)
        data.total = reduce(lambda res, x: res + int(x['price']), items.values(), 0)
        self.render('checkout.html', data=data)

    def post(self):
        data = Data()
        request = json.loads(self.request.body)
        # todo: допилить проверку полей
        if len(request['size']) == len(request['qty']) == len(request['color']):
            obj = dict(
                created=datetime.utcnow(),
                oid=int(data.db.system_js.getNextSequence('oid')),
                address=dict(
                    street=request['address'],
                    city=request['city'],
                    postcode=request['postcode'],
                    ssid=self.session.id,
                ),
                customer=dict(
                    first_name=request['first_name'],
                    last_name=request['last_name'],
                    email=request['email'],
                    tel=request['tel'],
                    comment=request['comment']
                ),
                shipment=list(
                    dict(
                        id=i,
                        size=request['size'][i],
                        quantity=request['qty'][i],
                        color=request['color'][i]
                    ) for i in request['qty']
                )
            )
            res = data.db.orders.insert_one(obj)
            if res.inserted_id:
                self.finish()
            else:
                raise tornado.web.HTTPError(500)
        else:
            raise tornado.web.HTTPError(404)

class Catalogue(BaseHandler):
    def get(self):
        data = Data()
        loader = Loader(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'templates'))
        items = data.db.items.find()
        data.cart_html = self.get_cart_html()
        data.cart_count = data.db.cart.find(dict(_id=self.session.id)).count()
        data.items = ''
        for item in items:
            data.items += loader.load('item.html').generate(
                id=item['_id'],
                name=item['name'],
                comment=item.get('comment', ''),
                price=item['price'],
                leader=False
            )
        self.render('catalogue.html', data=data)


class Cart(BaseHandler):
    def get(self):
        data = Data()
        data.leader = self.get_leader_html()
        data.cart_html = self.get_cart_html()
        data.cart_count = data.db.cart.find(dict(_id=self.session.id)).count()
        cart = data.db.cart.find_one(dict(_id=self.session.id))
        try:
            items = {r['_id']: r for r in
                     data.db.items.find({'_id': {'$in': map(lambda x: ObjectId(x), cart['iids'])}})}
        except TypeError:
            items = {}
        data.cart = items.values()
        data.sizes = ['M', 'S', 'L']
        data.colors = ['Белый', 'Черный']
        self.render('cart.page.html', data=data)

    def post(self):
        request = json.loads(self.request.body)
        if len(request):
            data = Data()
            options = dict(
                created=datetime.datetime.utcnow(),
                ssid=self.session.id,
                oid=int(data.db.system_js.getNextSequence('oid'))
            )
            request.update(options)
            res = data.db.orders.insert_one(request)
            if res.inserted_id:
                self.finish()
            else:
                raise tornado.web.HTTPError(500)
        else:
            raise tornado.web.HTTPError(404)


class Admin(BaseHandler):
    def get(self):
        data = Data()
        self.render('admin.html', data=data)


class AdminCategory(BaseHandler):
    def get(self):
        data = Data()
        data.cats = {c['_id']: c for c in data.db.categories.find()}
        for cat in data.cats.values():
            cat['qty'] = data.db.items.find({'category': cat.get('name', '')}).count()
        self.render('admin.category.html', data=data)

    def post(self):
        data = Data()
        request = json.loads(self.request.body)
        if 'name' in request:
            res = data.db.categories.insert_one(request)
            if res.inserted_id:
                self.write('/admin/category')
                self.finish()
            else:
                raise tornado.web.HTTPError(404)
        else:
            raise tornado.web.HTTPError(404)


class AdminCategoryDelete(BaseHandler):
    def post(self):
        data = Data()
        request = json.loads(self.request.body)
        if 'id' in request:
            res = data.db.categories.delete_one(dict(_id=ObjectId(request['id'])))
            if res.deleted_count:
                self.finish()
            else:
                raise tornado.web.HTTPError(404)
        else:
            raise tornado.web.HTTPError(404)


class AdminItems(BaseHandler):
    def get(self):
        data = Data()
        data.items = {i['_id']: i for i in data.db.items.find()}
        self.render('admin.items.html', data=data)


class AdminItemsAdd(BaseHandler):
    def get(self):
        data = Data()
        data.cats = data.db.categories.find()
        self.render('admin.item.add.html', data=data)

    def post(self):
        data = Data()
        request = self.dict_args
        try:
            picture_body = self.request.files['picture'][0]['body']
        except (KeyError, TypeError):
            picture_body = False
        if len(request) and picture_body:
            request.update(dict(
                created=datetime.utcnow(),
                created_by=self.get_current_user()
            ))
            item = data.db.items.insert_one(request)
            if item.inserted_id:
                try:
                    string_io = StringIO.StringIO(picture_body)
                    size = 200, 250
                    image = Image.open(string_io)
                    image.thumbnail(size, Image.ANTIALIAS)
                    image.save(IMAGE_DIR + str(item.inserted_id) + '.png', 'PNG')
                    self.redirect('/admin/items')
                except IOError:
                    raise tornado.web.HTTPError(500)
            else:
                raise tornado.web.HTTPError(404)
        else:
            raise tornado.web.HTTPError(404)


class AdminItemsDelete(BaseHandler):
    def post(self):
        request = json.loads(self.request.body)
        if 'id' in request:
            data = Data()
            res = data.db.items.delete_one(dict(_id=ObjectId(request['id'])))
            if res.deleted_count:
                data.purge(IMAGE_DIR, r'%s\..+' % request['id'])
                self.finish()
            else:
                raise tornado.web.HTTPError(404)
        else:
            raise tornado.web.HTTPError(404)


class AdminItemsSetLeader(BaseHandler):
    def post(self):
        request = json.loads(self.request.body)
        if 'id' in request:
            data = Data()
            #Clear previous leader
            data.db.items.update_many({'name': {'$exists': True}}, {'$unset': {'leader': True}})
            res = data.db.items.update_one(dict(_id=ObjectId(request['id'])), {'$set': dict(leader=True)})
            if res.modified_count:
                self.finish()
            else:
                raise tornado.web.HTTPError(404)
        else:
            raise tornado.web.HTTPError(404)


class Thumbnail(BaseHandler):
    def get(self, iid):
        iid = iid if iid else None
        if iid:
            data = Data()
            item = data.db.items.find_one(dict(_id=ObjectId(iid)))
            try:
                image = Image.open(IMAGE_DIR + str(item.get('_id', '')) + '.png')
                size = 128, 128
                image.thumbnail(size, Image.ANTIALIAS)
                f = StringIO.StringIO()
                image.save(f, 'PNG')
                self.set_header('Content-Type', 'Image/png')
                self.write(f.getvalue())
                self.finish()
            except IOError:
                print 'cannot open image'


class TornadoWebServer(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", Main),
            (r"/cart", Cart),
            (r"/profile", Profile),
            (r"/login", Login),
            (r"/register", Register),
            (r"/getcart", GetCartHTML),
            (r"/checkout", Checkout),
            (r"/catalogue", Catalogue),
            (r"/admin", Admin),
            (r"/admin/category", AdminCategory),
            (r"/admin/category/delete", AdminCategoryDelete),
            (r"/admin/items", AdminItems),
            (r"/admin/items/add", AdminItemsAdd),
            (r"/admin/items/edit", Admin),
            (r"/admin/items/delete", AdminItemsDelete),
            (r"/admin/items/setleader", AdminItemsSetLeader),
            (r"/admin/orders", Admin),
            (r"/thumbnail/(?P<iid>[a-zA-Z0-9]+)(?:$|/)", Thumbnail),
            (r"/payment/(?P<oid>[0-9])(?:$|/)", Payment),
            (r"/detail/(?P<iid>[a-zA-Z0-9]+)(?:$|/)", Detail),
            (r"/cartadditem/(?P<iid>[a-zA-Z0-9]+)(?:$|/)", AddItemToCart),
            (r"/cartdelitem/(?P<iid>[a-zA-Z0-9]+)(?:$|/)", DelItemFromCart)
        ]
        settings = dict(
            autoreload=True,
            debug=True,
            static_path='static/',
            static_file_prefix='',
            template_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'templates'),
            cookie_secret='djnnfrbtdjnghbjujb',
            login_url='/login',
            xsrf_cookies=False,
        )
        session_settings = dict(
            driver="memory",
            driver_settings=dict(
                host=self,
            ),
            force_persistence=True,
        )
        settings.update(session=session_settings)
        tornado.web.Application.__init__(self, handlers,**settings)


if __name__ == '__main__':
    print('[*] Waiting for http requests')
    logging.basicConfig(filename="/tmp/control-panel.log", level=logging.DEBUG)
    application = TornadoWebServer()
    application.mongo = MongoClient()
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(8000)
    http_server.start()
    ioloop = tornado.ioloop.IOLoop.instance()
    ioloop.start()
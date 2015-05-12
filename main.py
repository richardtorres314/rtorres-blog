import os
import webapp2
import jinja2

from google.appengine.ext import db
from datetime import datetime
import time
import pytz
from pytz import timezone
import json
from time import strftime
import hashlib
import math

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class User(db.Model):
    username = db.StringProperty()
    password = db.StringProperty()
    email = db.StringProperty()

class Blog(db.Model):
    subject = db.StringProperty()
    content = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add = True)
    updated = db.DateTimeProperty()
    author = db.StringProperty()

CACHE = {}
class MainHandler(Handler):
    
    def query(self):
        key = 'latest'
        if key in CACHE:
            entries = CACHE[key]
        else:
            entries = db.GqlQuery("Select * from Blog ORDER BY created desc")
            entries = list(entries)
            CACHE[key] = entries
        return entries
        
    def write_form(self, page_no):
        page_no = int(page_no)
        entries = self.query()
        page_nos = int(math.ceil(len(entries)/5))
        if page_no > page_nos:
            self.redirect('/blog')
        else:
            entries = entries[(page_no-1)*5:(page_no-1)*5+4]
            cookie = self.request.cookies.get('user_id')
            username = ""
            if cookie:
                username = cookie[:cookie.find('|')]
            self.render("index.html", subject="", content="", error="", page_nos = page_nos, page_no = page_no,
                    entries=entries, blog_id=0, username=username)

    def get(self, page_no = 1):
        self.write_form(page_no = page_no)

class PostHandler(Handler):
    def write_form(self, username):
        self.render("newpost.html", username=username)

    def get(self):
        cookie = self.request.cookies.get('user_id')
        username = cookie[:cookie.find('|')]
        if username:
            self.write_form(username=username)
        else:
            self.redirect('/blog/signup')

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        cookie = self.request.cookies.get('user_id')
        author = cookie[:cookie.find('|')]
        if subject and content and author:
            b = Blog(subject = subject, content = content, author = author)
            b.put()
            blog_id = b.key().id()
            CACHE['latest'].insert(0,b)
            self.redirect("/blog/%d" % blog_id)
        else:
            error = "Please fill the form completely"
            self.render("newpost.html", subject = subject, content = content, error = error)

class Permalink(Handler):
    def get(self, blog_id):
        cookie = self.request.cookies.get('user_id')
        username = cookie[:cookie.find('|')]
        entry = Blog.get_by_id(int(blog_id))
        if entry:
            subject = entry.subject
            content = entry.content
            blog_id = entry.key().id()
            created = entry.created
            updated = entry.updated
            author = entry.author
            self.render("blog.html", subject = subject, content = content, blog_id = blog_id,
                        created = created, author = author, username = username, updated = updated)
        else:
            self.redirect('/blog')

    def post(self, blog_id):
        for entry in CACHE['latest']:
            if str(entry.key().id()) == str(blog_id):
                CACHE['latest'].remove(entry)
        entry = Blog.get_by_id(int(blog_id))
        entry.delete()
        self.redirect('/blog')

class SignupHandler(Handler):
    def write_form(self):
        self.render("signup.html",
                    username = "", error_user = "",
                    error_password = "", error_verify = "",
                    email = "")
        
    def get(self):
        self.write_form()

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        passhash = hashlib.md5(password).hexdigest()
        verifyhash = hashlib.md5(verify).hexdigest()
        error_user = ""
        error_password = ""
        error_verify = ""
        user_check = db.GqlQuery("Select * from User where username = :1", username)
        if username and user_check.count() == 0 and password and verify and password == verify:
            self.response.headers.add_header('Set-Cookie', 'user_id=%s|%s; Path=/' % (str(username), str(passhash)))
            user = User(username = username, password = passhash, email = email)
            user.put()
            self.redirect('/blog')
        else:
            if user_check.count() is not 0:
                error_user = "That user already exists"
            if not username:
                error_user = "Please enter a username"
            if not password:
                error_password = "Please enter a password"
            if verify != password:
                error_verify = "Please enter the same password"
            self.render("signup.html",
                            username = username, error_user = error_user,
                            error_password = error_password,
                            error_verify = error_verify,
                            email = email)

class LoginHandler(Handler):
    def write_form(self):
        self.render("login.html")

    def get(self):
        self.write_form();

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        passhash = hashlib.md5(password).hexdigest()
        user_check = db.GqlQuery("Select * from User where username = :username and password = :password", username = username, password = passhash)
        if user_check.count() == 1:
            self.response.headers.add_header('Set-Cookie', 'user_id=%s|%s; Path=/' % (str(username), str(passhash)))
            self.redirect('/blog')
        else:
            error_user = "Sorry, invalid login"
            self.render("login.html", error_user = error_user)

class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/blog')

class JsonHandler(Handler):
    def write_form(self, blog_id):
        d = {}
        l = []
        if blog_id:
            entries = db.GqlQuery("Select * from Blog where __key__ = KEY('Blog', %s)" % blog_id)
        else:
            entries = db.GqlQuery("Select * from Blog")
        if entries.count() > 0:
            self.response.headers['Content-Type'] = "application/json"
            for entry in entries:
                d = ({'subject': entry.subject,
                    'blog_id' : entry.key().id(),
                    'content': entry.content,
                    'created': str(entry.created.strftime("%a %b %d %H:%M:%S %Y"))})
                l.append(d)
            self.response.out.write(json.dumps(l))

    def get(self, blog_id = ""):
        self.write_form(blog_id = blog_id)

class FlushHandler(Handler):
    def get(self):
        self.write_form()

    def write_form(self):
        CACHE.clear()
        self.redirect('/')

class EditHandler(Handler):
    def get(self, blog_id):
        self.write_form(blog_id = blog_id)

    def write_form(self, blog_id):
        entry = Blog.get_by_id(int(blog_id))
        subject = entry.subject
        content = entry.content
        self.render('edit.html', subject = subject, content = content,
                    blog_id = blog_id)

    def post(self, blog_id):
        subject = self.request.get('subject')
        content = self.request.get('content')
        entry = Blog.get_by_id(int(blog_id))
        if subject and content:
            entry.subject = subject
            entry.content = content
            entry.updated = datetime.now()
            entry.put()
            self.redirect("/blog/%d" % int(blog_id))
        else:
            self.render("edit.html", blog_id = blog_id, subject = entry.subject, content = entry.content, error = "Please fill out the form completely.")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/blog/?', MainHandler),
    ('/blog/page/(\d+)', MainHandler),
    ('/blog/newpost', PostHandler),
    ('/blog/(\d+)', Permalink),
    ('/blog/(\d+).json', JsonHandler),
    ('/blog/.json', JsonHandler),
    ('/blog/signup', SignupHandler),
    ('/blog/login', LoginHandler),
    ('/blog/logout', LogoutHandler),
    ('/blog/flush', FlushHandler),
    ('/blog/(\d+)/edit', EditHandler),
], debug=True)

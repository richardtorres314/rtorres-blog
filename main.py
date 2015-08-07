"""
File:               main.py
Author:             Richard Torres
Date:               8/7/2015
Revision: 1.0.0     First official release version
To do:              Add "like" feature
                    Allow for user to access their personal entries
"""

import os
import webapp2
import jinja2

from google.appengine.ext import db
from datetime import datetime
import time
from pytz import timezone
import json
from time import strftime
import hashlib
import math

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

# @desc Method for generating a secure hash for the user password using the
# MD5 hashing algorithm. This password is stored onto the database for security
# purposes.
# @return The hashed password as a string
def make_pass_hash(password):
    pass_hash = hashlib.md5(password).hexdigest()
    return pass_hash

# @desc Method for verifying that the hashed password user input is
# equal to the given hashed password (stored in the database)
# @return A boolean statement indicating whether the hashed passwords are equal
def verify_pass_hash(verify, pass_hash):
    return pass_hash == make_pass_hash(verify)

# @desc Method for accessing the user's ID from a set cookie.
# @return The user's ID as a string
def get_username(cookie):
    return cookie[:cookie.find('|')]

# @desc Method for getting the hashed password from the stored cookie.
# @return The string of the hashed password. Returns the empty string
# if the cookie is invalid or not set.
def get_pass_hash(cookie):
    return cookie[cookie.find('|')+1:]

# @desc Method to check if username is in database.
# @return Boolean statement indicating that the user exists
def user_check(username, password):
    user = db.GqlQuery("Select * from User where username = :username and password = :password", username = username, password = password)
    return user.count() == 1

# @desc Method to check if user is authenticated user stored in the CACHE
# return Boolean statement indicating the key value pair is valid
def auth_check(username, password):
    check = 0
    if str(username) in CACHE:
        check = CACHE[str(username)] == str(password)
    return check

# @desc Sets a test cookie, used to determine if user has cookies enabled.
def set_test_cookie(self):
    self.response.headers.add_header('Set-Cookie', 'test=true; Path=/')

# @desc Tests whether the test cookie has been set.
# @return Boolean statement indicating if the cookie has been set.
def test_cookie_worked(self):
    cookie = self.request.cookies.get('test')
    val = False
    if cookie:
        val = True
    return val

# @desc Gets a cookie set on the user's computer
# @return String representation of the specified cookie in the parameter
def get_cookie(self, cookie_name):
    return self.request.cookies.get(cookie_name)

# @desc Clears the specified cookie in the paramenter
def clear_cookie(self, cookie_name):
    self.response.headers.add_header('Set-Cookie', cookie_name+'=; Path=/')

# @desc Checks to see if the cache has the blog entries stored. If not, the
# database is queried and the entries are stored to the cache for future use.
def query():
    key = 'latest'
    if key in CACHE:
        entries = CACHE[key]
    else:
        entries = db.GqlQuery("Select * from Blog ORDER BY created desc")
        entries = list(entries)
        CACHE[key] = entries
    return entries


"""
" Model Definitions
"""

#    @desc User model definition
class User(db.Model):
    username = db.StringProperty()
    password = db.StringProperty()
    email = db.StringProperty()

# @desc Blog model definition
class Blog(db.Model):
    subject = db.StringProperty()
    content = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add = True)
    updated = db.DateTimeProperty()
    author = db.StringProperty()

# @desc boilerplate for rendering all templates
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw)

# @ desc Cache for optimization. The database is queried only if the cache
# does not contain the blog entries. Once queried, the cache will append the
# blog entries which will proceed to populate the paginated page.
CACHE = {}

"""
" 'Controllers' in traditional MVC architectural pattern
"""

# @desc Class definition for '/' route
# HTTP GET verb defined
class MainHandler(Handler):
    def get(self):
        self.write_form()

    def write_form(self):
        self.render('index.html')

# @desc Class definition for '/blog' route
# HTTP GET verb defined
class BlogHandler(Handler):
    
    # @desc Writes the homepage with the entries stored in the cache.
    # The entries are paginated in chronologically descending order. 
    def write_form(self, page_no):
        page_no = int(page_no)
        entries = query()
        page_nos = int(math.ceil(len(entries)/5.0))
        if page_no > page_nos:
            self.redirect('/blog')
        else:
            entries = entries[(page_no-1)*5:(page_no-1)*5+4]
            cookie = self.request.cookies.get('user_id')
            username = ""
            if cookie:
                username = get_username(cookie)
                pass_hash = get_pass_hash(cookie)
                if auth_check(username, pass_hash) != 1:
                    clear_cookie(self, 'user_id')
                    username = ''
                    pass_hash = ''
            self.render("blog_index.html", subject="", content="", error="", page_nos = page_nos, page_no = page_no,
                        entries=entries, blog_id=0, username=username)
    
    # @desc GETs blog entries from current page number (defaults to 1 if none set)
    # sets a test cookie to verify that cookies are enabled
    def get(self, page_no = 1):
        set_test_cookie(self)
        self.write_form(page_no)

# @desc Class definition for '/newpost' route
# HTTP GET, POST verbs defined
class PostHandler(Handler):
    def write_form(self, username):
        self.render("newpost.html", username=username)

    # @desc Checks if test cookie was set
    # If set, clears test cookie, then checks if user is currently logged in
    # If so, retrieves information from set cookie, if not users are redirected
    # to a signup page. If test cookie failed, user is redirected to a page
    # indicating that cookies must be enabled to signup/login.
    def get(self):
        if test_cookie_worked(self):
            clear_cookie(self, 'test')
            cookie = self.request.cookies.get('user_id')
            if cookie:
                username = get_username(cookie)
                pass_hash = get_pass_hash(cookie)
                if username and auth_check(username, pass_hash):
                    self.write_form(username=username)
                else:
                    self.redirect('/blog/signup')
            else:
                self.redirect('/blog/signup')
        else:
            self.render('cookies.html')

    # @desc Checks to see that the new post form was filled out properly
    # and that the user is still logged in. If not, user is redirected to
    # signup page. If so, the entry is stored to the database as well as the
    # cache. The user is then redirected to a permalink page for the new
    # entry. If the form is invalid/incomplete, the user is redirected to the
    # new post page with what they have entered.
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        cookie = get_cookie(self, 'user_id')
        author = get_username(cookie)
        pass_hash = get_pass_hash(cookie)
        if not auth_check(author, pass_hash):
            self.redirect('/blog/signup')
        elif subject and content and author:
            b = Blog(subject = subject, content = content, author = author)
            b.put()
            blog_id = b.key().id()
            CACHE['latest'].insert(0,b)
            self.redirect("/blog/%d" % blog_id)
        else:
            error = "Please fill the form completely"
            self.render("newpost.html", subject = subject, content = content, error = error)

# @desc Class definition for custom permalink route
# HTTP GET, POST verbs defined
class Permalink(Handler):

    # @desc GETs an entry by permalink ID. If ID exists, user is directed to page
    # If ID does not exist, user is directed to the homepage. If the user is the
    # author, they are given the option to edit and delete a post.
    def get(self, blog_id):
        cookie = self.request.cookies.get('user_id')
        username = ''
        if cookie:
            username = get_username(cookie)
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

    # @desc POSTs an entry by permalink ID. If ID exists and user is author, the
    # author will be allowed to delete the entry. The entry is then removed from
    # the database.
    def post(self, blog_id):
        for entry in CACHE['latest']:
            if str(entry.key().id()) == str(blog_id):
                CACHE['latest'].remove(entry)
        entry = Blog.get_by_id(int(blog_id))
        entry.delete()
        self.redirect('/blog')

# Class definition for '/signup' route
# HTTP GET, POST verbs defined
class SignupHandler(Handler):
    def write_form(self):
        self.render("signup.html",
                    username = "", error_user = "", error_password = "",
                    error_verify = "", email = "")

    # @desc GETs signup form. If user is already logged on (a valid cookie is
    # set, the user is redirected to homepage. Else if the user does not have
    # cookies enabled, user is sent to error page indicating so. Else, user is
    # not logged in and is sent to the signup page.
    def get(self):
        if test_cookie_worked(self):
            cookie = self.request.cookies.get('user_id')
            if cookie:
                username = get_username(cookie)
                pass_hash = get_pass_hash(cookie)
                if not auth_check(username, pass_hash):
                    self.write_form()
                else:
                    self.redirect('/blog')
            else:
                self.write_form()
        else:
            self.render('cookies.html')

    # @desc POSTs signup form. If user's information is valid, the user is
    # securely stored onto the database, and a cookie is generated. If the
    # selected username is chosen, the user is redirected back to form with
    # an appropriate error message. If a portion of the form is incomplete,
    # the user is redirected back to the form with an appropriate message.
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        pass_hash = make_pass_hash(password)
        verifyhash = verify_pass_hash(verify, pass_hash)
        error_user = ""
        error_password = ""
        error_verify = ""
        user = user_check(username, pass_hash)
        if username and not user and password and verify == 1:
            self.response.headers.add_header('Set-Cookie', 'user_id=%s|%s; Path=/' % (str(username), str(passhash)))
            user = User(username = username, password = passhash, email = email)
            user.put()
            self.redirect('/blog')
        else:
            if user:
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
                            error_verify = error_verify, email = email)

# Class definition for '/login' route
# HTTP GET, POST verbs defined
class LoginHandler(Handler):
    def write_form(self):
        self.render("login.html")

    # GETs login form. If a user is already logged in (valid cookie is set),
    # the user is redirected to homepage. If the user's cookies are not enabled,
    # the user is redirected to error message indicating the user must enable
    # cookies to use the site. Else, the user is directed to login form.
    def get(self):
        if test_cookie_worked(self):
            cookie = get_cookie(self, 'user_id')
            if cookie:
                username = get_username(cookie)
                pass_hash = get_pass_hash(cookie)
                if auth_check(username, pass_hash):
                    self.redirect('/blog')
                else:
                    self.write_form()
            else:
                self.write_form()
        else:
            self.render('cookies.html')

    # @desc POST to login form. If the provided login information is invalid,
    # the user is redirected back to the form with an appropriate error message.
    # Else if the information is valid, the user is logged in and a cookie is
    # set with the user information.
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        pass_hash = make_pass_hash(password)
        user = user_check(username, pass_hash)
        if user:
            self.response.headers.add_header('Set-Cookie', 'user_id=%s|%s; Path=/' % (str(username), str(pass_hash)))
            CACHE[str(username)] = str(pass_hash)
            self.redirect('/blog')
        else:
            error_user = "Sorry, invalid login"
            self.render("login.html", error_user = error_user)

# Class definition of '/logout' route
# HTTP GET verb defined
class LogoutHandler(Handler):
    # GETs logout process. The cookie on the user's computer is cleared
    # and the user is redirected to homepage.
    def get(self):
        clear_cookie(self, 'user_id')
        self.redirect('/blog')

# Class definition for '.json' route
# HTTP GET verb defined
class JsonHandler(Handler):
    # @desc For all entries queried from the database by a user, the
    # entries are parsed to JSON.
    def write_form(self, blog_id):
        d = {}
        l = []
        if blog_id:
            entries = db.GqlQuery("Select * from Blog where __key__ = KEY('Blog', %s)" % blog_id)
        else:
            entries = query()
        if entries.count() > 0:
            self.response.headers['Content-Type'] = "application/json"
            for entry in entries:
                d = ({'subject': entry.subject,
                    'blog_id' : entry.key().id(),
                    'content': entry.content,
                    'created': str(entry.created.strftime("%a %b %d %H:%M:%S %Y"))})
                l.append(d)
            self.response.out.write(json.dumps(l))

    # @desc GETs the write_form method which generates the entry/entries
    # as a JSON file.
    def get(self, blog_id = ""):
        self.write_form(blog_id = blog_id)

# Class definition for '/flush' route
# HTTP GET verb defined
class FlushHandler(Handler):
    # @desc GETs the write_form method which clears the cache.
    def get(self):
        self.write_form()

    # @desc Method for clearing the cache. Redirects a user back to the homepage.
    def write_form(self):
        CACHE.clear()
        self.redirect('/blog')

# Class definition for '/edit' route
# HTTP GET, POST verbs defined
class EditHandler(Handler):

    # @desc GETs edit form. If user is logged in (valid cookie set), the
    # write_form method generates the edit form with the entry's information
    # Else if the user is not logged in, the user is sent to the signup form.
    def get(self, blog_id):
        cookie = self.request.cookies.get('user_id')
        username = get_username(cookie)
        pass_hash = get_pass_hash(cookie)
        if username and auth_check(username, pass_hash):
            self.write_form(blog_id = blog_id, username = username)
        else:
            clear_cookie(self, 'user_id')
            self.redirect('/blog/signup')

    # @desc This method writes the edit form with the post's current information.
    def write_form(self, blog_id, username):
        entry = Blog.get_by_id(int(blog_id))
        subject = entry.subject
        content = entry.content
        self.render('newpost.html', subject = subject, content = content,
                    blog_id = blog_id, username = username)

    # @desc POSTs edited form. Checks if user is authenticated and entry is
    # appropriately filled out. If not authenticated, user is redirected to
    # signup form. If the form is invalid, the user is redirected back to edit
    # form with newly modified content. User may cancel editing and keep the
    # original content.
    def post(self, blog_id):
        subject = self.request.get('subject')
        content = self.request.get('content')
        entry = Blog.get_by_id(int(blog_id))
        cookie = self.request.cookies.get('user_id')
        username = get_username(cookie)
        pass_hash = get_pass_hash(cookie)
        if username and auth_check(username, pass_hash):
            if subject and content:
                if not (subject == entry.subject and content == entry.content):
                    entry.subject = subject
                    entry.content = content
                    entry.updated = datetime.now()
                    entry.put()
                    self.redirect("/blog/%d" % int(blog_id))
                else:
                    msg = "Please edit the entry."
                    self.render("newpost.html", blog_id = blog_id, subject = entry.subject,
                            content = entry.content, username = username, error = msg)
            else:
                msg = "Please fill out the form completely."
                self.render("newpost.html", blog_id = blog_id, subject = entry.subject,
                            content = entry.content, username = username, error = msg)
        else:
            clear_cookie(self, 'user_id')
            self.redirect('/blog/signup')

# Class definition '/cookies' route
# HTTP GET verb defined
class CookieHandler(Handler):
    # @desc GETs write_form method which generates the error page telling user
    # to enable cookies.
    def get(self):
        self.write_form()

    # @desc Method renders the cookie template
    def write_form(self):
        self.render('cookies.html')


"""
" Routes to application
"""
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/blog/?', BlogHandler),
    ('/blog/page/(\d+)', BlogHandler),
    ('/blog/newpost', PostHandler),
    ('/blog/(\d+)', Permalink),
    ('/blog/(\d+).json', JsonHandler),
    ('/blog/.json', JsonHandler),
    ('/blog/signup', SignupHandler),
    ('/blog/login', LoginHandler),
    ('/blog/logout', LogoutHandler),
    ('/blog/flush', FlushHandler),
    ('/blog/(\d+)/edit', EditHandler),
    ('/blog/cookies', CookieHandler)
], debug=True)

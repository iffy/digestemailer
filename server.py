import requests
import sys
import json
import os
import scrypt
from klein import Klein
from requests.auth import HTTPBasicAuth
from bs4 import BeautifulSoup as BS4
from twisted.python import usage, log
from twisted.python.filepath import FilePath
from twisted.internet import task, reactor, threads, defer, endpoints
from twisted.web.server import Site

from keyczar.keys import AesKey, HmacKey
from keyczar import util


def makeKey(password, size=32):
    key_bytes = scrypt.hash(password, 'some insecure salt', buflen=size)
    key_string = util.Base64WSEncode(key_bytes)
    hmac_key = HmacKey(key_string)
    return AesKey(key_string, hmac_key, size)


def encrypt(string, password):
    key = makeKey(password)
    return key.Encrypt(string)


def decrypt(cipher, password):
    key = makeKey(password)
    return key.Decrypt(cipher)


class Sender(object):

    heartbeat_interval = 7 * 24 * 60 * 60
    heartbeat_delay = 60 * 60
    notify_interval = 24 * 60 * 60
    notify_delay = 60
    dryrun = False
    password = None

    def __init__(self, filestore, api_root, send_from, send_to):
        self.filestore = FilePath(filestore)
        self.api_root = api_root
        self.send_from = send_from
        self.send_to = send_to
        self.api_key = None
        self.accounts = {}
        self.last_send_succeeded = True

        self._heartbeat_lc = None
        self._heartbeat_dc = None
        self._notify_lc = None
        self._notify_dc = None


    def _load(self):
        if self.password:
            if self.filestore.exists():
                contents = self.filestore.getContent()
                if contents:
                    self.accounts = json.loads(decrypt(contents, self.password))
                else:
                    log.msg('No contents')
            else:
                log.msg('No filestore')
        else:
            self.notifyProblem("Missing the decryption key")


    def _save(self):
        if self.password:
            self.filestore.setContent(
                encrypt(json.dumps(self.accounts).encode('utf-8'),
                        self.password))


    def restart(self):
        if self._heartbeat_dc and self._heartbeat_dc.active():
            self._heartbeat_dc.cancel()
        if self._heartbeat_lc and self._heartbeat_lc.running:
            self._heartbeat_lc.stop()

        if self._notify_dc and self._notify_dc.active():
            self._notify_dc.cancel()
        if self._notify_lc and self._notify_lc.running:
            self._notify_lc.stop()

        self._heartbeat_lc = task.LoopingCall(self.sendMessage, 'Heartbeat',
                                              'Status: Alive')
        self._heartbeat_dc = reactor.callLater(
            self.heartbeat_delay,
            self._heartbeat_lc.start,
            self.heartbeat_interval)
        
        self._notify_lc = task.LoopingCall(self.getAndSendDigest)
        self._notify_dc = reactor.callLater(
            self.notify_delay,
            self._notify_lc.start,
            self.notify_interval)
        # from now on, notify immediately
        self.notify_delay = 0


    def setMasterPassword(self, password):
        self.password = password
        self._load()


    def addAccount(self, email, password):
        self.accounts[email] = password
        self._save()


    @defer.inlineCallbacks
    def sendMessage(self, subject, message):
        log.msg('sending message')
        if not self.api_key:
            self.notifyProblem("Missing API key")
            return
        data = json.dumps({
            'key': self.api_key,
            'message': {
                'text': message,
                'subject': subject,
                'from_email': self.send_from,
                'from_name': 'Gmail monitor',
                'to': [self.send_to],
            }
        })
        if self.dryrun:
            log.msg('Would have sent: %r' % (data,))
        else:
            try:
                r = yield threads.deferToThread(requests.post,
                    self.api_root + '/messages/send.json',
                    data=data,
                    headers={
                        'Content-Type': 'application/json',
                    }
                )
                if r.ok:
                    self.last_send_succeeded = True
                else:
                    log.msg(r.text)
                    raise Exception(r.text)
            except Exception as e:
                self.last_send_succeeded = False
                self.notifyProblem("sending message failed: %s" % (e,))


    def notifyProblem(self, problem):
        log.msg(problem, system='problem')
        if self.api_key and self.last_send_succeeded:
            self.sendMessage("Problem", problem)


    @defer.inlineCallbacks
    def getAndSendDigest(self):
        if not self.password:
            self.notifyProblem("Password not set")
            return
        if not self.accounts:
            self.notifyProblem("There are no accounts set up")
            return
        account_messages = []
        for email, password in self.accounts.items():
            messages = yield threads.deferToThread(
                self._getUnreadMessages, email, password)
            account_messages.append((email, messages))

        # only send if there's something to send
        total_unread = sum([len(x[1]) for x in account_messages])
        if not total_unread:
            return

        # format subject and body
        subject = '%d unread messages from %d other accounts' % (
            total_unread, len(account_messages))
        lines = []
        for email, messages in account_messages:
            lines.append('-'*40)
            lines.append('From %s' % (email,))
            lines.append('-'*40)
            for message in messages:
                lines.append(message)
            lines.append('')
        body = '\n'.join(lines)

        self.sendMessage(subject, body)


    def _getUnreadMessages(self, email, password):
        log.msg('Checking %s' % (email,))
        r = requests.get('https://mail.google.com/mail/feed/atom',
                         auth=HTTPBasicAuth(email, password))
        soup = BS4(r.text)
        ret = []
        for entry in soup.find_all('entry'):
            title = entry.find('title')
            time = entry.find('modified')
            ret.append('%s - %s' % (time.getText(), title.getText()))
        return ret


class SenderApp(object):

    app = Klein()

    def __init__(self, html, sender):
        self.html = html
        self.sender = sender

    @app.route('/')
    def index(self, request):
        return open(self.html, 'rb').read()


    @app.route('/password', methods=['GET'])
    def isPasswordSet(self, request):
        if self.sender.password:
            return json.dumps(True)
        else:
            return json.dumps(False)

    @app.route('/password', methods=['POST'])
    def setPassword(self, request):
        data = json.loads(request.content.read())
        password = data['password'].encode('utf-8')
        self.sender.setMasterPassword(password)


    @app.route('/accounts', methods=['GET'])
    def accounts(self, request):
        return json.dumps(self.sender.accounts.keys())


    @app.route('/accounts', methods=['POST'])
    def addAccount(self, request):
        data = json.loads(request.content.read())
        email = data['email']
        password = data['password']
        self.sender.addAccount(email, password)


    @app.route('/check-now', methods=['POST'])
    def checkNow(self, request):
        self.sender.restart()



class Options(usage.Options):

    optFlags = [
        ('dryrun', 'n', "Don't actually send email"),
    ]

    optParameters = [
        ('web-endpoint', 'w', 'tcp:9700', "Web endpoint"),
        ('html-file', 'H', 'index.html', "HTML file"),
        ('alive-interval', 'A', 7 * 24 * 60 * 60,
            "Number of seconds between, notifications that the script "
            "is running"),
        ('interval', 'i', 24 * 60 * 60,
            "Interval in seconds between email checks and notifications"),
        ('mandrill-root', None, 'https://mandrillapp.com/api/1.0',
            "Root of Mandrill api"),
        ('state', 'S', '.state.json', "Encrypted state file"),
        ('send-to', 's', None, "Send digest emails to this email address"),
        ('send-from', 'f', None, "Send digest emails from this email address"),
    ]

if __name__ == '__main__':
    options = Options()
    options.parseOptions()

    log.startLogging(sys.stdout)

    root = options['mandrill-root']
    
    sender = Sender(options['state'], root, options['send-from'], options['send-to'])
    sender.dryrun = options['dryrun']
    sender.api_key = os.environ.get('MANDRILL_API_KEY', None)
    app = SenderApp(options['html-file'], sender)

    site = Site(app.app.resource())
    ep = endpoints.serverFromString(reactor, options['web-endpoint'])
    ep.listen(site)

    sender.restart()

    reactor.run()

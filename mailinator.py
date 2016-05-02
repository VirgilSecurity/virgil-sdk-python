import sys
import json
python_version = sys.version_info[0]
if python_version == 3:
    import urllib.request as urllib2
    from urllib.parse import urlencode
else:
    import urllib2
    from urllib import urlencode


class MailinatorInbox:
    def __init__(self, token):
        self.token = token
        self.url = 'https://api.mailinator.com/api/inbox'

    def get_last_id(self, mailbox):
        values = {'to': mailbox, 'token': self.token}
        inbox = send_request(self.url, values)
        messages = json.loads(inbox.decode())
        return messages['messages'][-1]['id']


class MailinatorEmail:
    def __init__(self, token):
        self.token = token
        self.url = 'http://api.mailinator.com/api/email'

    def get_email(self, mail_id):
        values = {'msgid': mail_id, 'token': self.token}
        return send_request(self.url, values).decode()


def send_request(url, values):
    data = urlencode(values)
    req = urllib2.Request(url + '?' + data)
    response = urllib2.urlopen(req)
    return response.read()


def receive_code(token, username):
    inbox = MailinatorInbox(token)
    emails = MailinatorEmail(token)
    for i in range(10):
        try:
            email_id = inbox.get_last_id(username)
            message = emails.get_email(email_id)
            if json.loads(message)['data']['seconds_ago'] > 10:
                continue
            code = message[message.find(r'bold;\">')+8:message.find(r'bold;\">')+14]
            return code
        except:
            continue
    raise ValueError('Email has not been received')

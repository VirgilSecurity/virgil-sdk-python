import urls as urls


class Chat(urls.Urls):
    def __init__(self, url, channel_name, identifier):
        self.url = url
        self.channel_name = channel_name
        url = self.url + '/channels/' + self.channel_name + '/join'
        values = {'identifier': identifier}
        self.identity_token = urls.json.loads(self.request('POST', url, None, values).decode())['identity_token']

    def join_channel(self, identifier):
        url = self.url + '/channels/' + self.channel_name + '/join'
        values = {'identifier': identifier}
        return urls.json.loads(self.request('POST', url, None, values))

    def channel_members(self):
        url = self.url + '/channels/' + self.channel_name + '/members'
        headers = {'X-IDENTITY-TOKEN': self.identity_token}
        return urls.json.loads(self.request('GET', url, headers, None))

    def post_message(self, message):
        url = self.url + '/channels/' + self.channel_name + '/messages'
        headers = {'X-IDENTITY-TOKEN': self.identity_token}
        headers['Content-Type'] = 'application/json'
        values = {'message': message}
        self.request('POST', url, headers, values)

    def get_messages(self, last_message_id):
        url = self.url + '/channels/' + self.channel_name + '/messages'
        headers = {'X-IDENTITY-TOKEN': self.identity_token}
        values = {'last_message_id': last_message_id}
        return urls.json.loads(self.request('GET', url, headers, values).decode())


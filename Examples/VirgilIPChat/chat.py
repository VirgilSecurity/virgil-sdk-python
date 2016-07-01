import urls


class Chat(urls.Urls):
    def __init__(self, url, channel_name, identifier):
        self.url = url
        self.channel_name = channel_name
        self.identity_token = self.join_channel(identifier)['identity_token']

    def join_channel(self, identifier):
        url = self.url + '/channels/' + self.channel_name + '/join'
        values = {'identifier': identifier}
        return urls.json.loads(self.request('POST', url, {'Content-Type': 'application/json'}, values))

    def channel_members(self):
        url = self.url + '/channels/' + self.channel_name + '/members'
        headers = {'X-IDENTITY-TOKEN': self.identity_token}
        return urls.json.loads(self.request('GET', url, headers, None))

    def post_message(self, message_model):
        url = self.url + '/channels/' + self.channel_name + '/messages'
        headers = {'X-IDENTITY-TOKEN': self.identity_token, 'Content-Type': 'application/json'}
        self.request('POST', url, headers, message_model)

    def get_messages(self, last_message_id):
        url = self.url + '/channels/' + self.channel_name + '/messages'
        headers = {'X-IDENTITY-TOKEN': self.identity_token}
        values = {'last_message_id': last_message_id}
        return urls.json.loads(self.request('GET', url, headers, values))

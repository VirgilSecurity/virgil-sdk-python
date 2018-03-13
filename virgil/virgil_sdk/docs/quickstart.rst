Quickstart
==========

------------------
Encryption Example
------------------

Virgil Security makes it super easy to add encryption to any application. With our SDK you create a public `Virgil Card <guide_virgil_cards_>`_ for every one of your users and devices. With these in place you can easily encrypt any data in the client.

.. code-block:: python

   # find Alice's card(s)
   alice_card = virgil.cards.find("alice")

   # encrypt the message using Alice's cards
   message = "Hello Alice!"
   encrypted_message = alice_cards.encrypt(message)

   # transmit the message with your preferred technology
   transmit_message(encrypted_message.to_string("base64"))


The receiving user then uses their stored **private key** to decrypt the message.


.. code-block:: python

    # load Alice's Key from storage.
    alice_key = virgil.keys.load("alice_key_1", "mypassword")

    # decrypt the message using the key
    original_message = alice_key.decrypt(transfer_data).to_string()

**Next:** To `get you properly started <guide_encryption_>`_ you'll need to know how to create and store Virgil Cards. Our `Get Started guide <guide_encryption_>`_ will get you there all the way.

**Also:** `Encrypted communication <getstarted_encryption_>`_ is just one of the few things our SDK can do. Have a look at our guides on `Encrypted Storage <getstarted_storage_>`_, `Data Integrity <getstarted_data_integrity_>`_ and `Passwordless Login <getstarted_passwordless_login_>`_ for more information.

--------------
Initialization
--------------

To use this SDK you need to `sign up for an account <https://developer.virgilsecurity.com/account/signup>`_ and create your first **application**. Make sure to save the **app id**, **private key** and it's **password**. After this, create an **application token** for your application to make authenticated requests from your clients.

To initialize the SDK on the client side you will only need the **access token** you created.

.. code-block:: python

    virgil = Virgil("[ACCESS_TOKEN]")

.. note::

    **Note:** this client will have limited capabilities. For example, it will be able to generate new **Cards** but it will need a server-side client to transmit these to Virgil.

To initialize the SDK on the server side we will need the **access token**, **app id** and the **App Key** you created on the `Developer Dashboard <https://developer.virgilsecurity.com/account/dashboard>`_.

.. code-block:: python

    key_file_content = open("[YOUR_APP_KEY_FILEPATH_HERE]", "r").read()
    raw_private_key = VirgilCrypto().strtobytes(key_file_content)

    creds = Credentials(
        app_id="[YOUR_APP_ID_HERE]",
        app_key=raw_private_key,
        app_password="[YOUR_APP_KEY_PASSWORD_HERE]"
    )

    context = VirgilContext(
        access_token="[YOUR_ACCESS_TOKEN_HERE]",
        credentials=creds
    )
    virgil = Virgil(context=context)

**Next:** `Learn more about our the different ways of initializing the Python SDK <guide_initialization_>`_ in our documentation.

-------------
Documentation
-------------

Virgil Security has a powerful set of APIs, and the documentation is there to get you started today.

* `Get Started <getstarted_root_>`_ documentation

  * `Initialize the SDK <initialize_root_>`_
  * `Encrypted storage <getstarted_storage_>`_
  * `Encrypted communication <getstarted_encryption_>`_
  * `Data integrity <getstarted_data_integrity_>`_
  * `Passwordless login <getstarted_passwordless_login_>`_
* `Guides <guides_>`_

  * `Virgil Cards <guide_virgil_cards_>`_
  * `Virgil Keys <guide_virgil_keys_>`_

-------
License
-------

This library is released under the `3-clause BSD License <https://github.com/VirgilSecurity/virgil-sdk-python/blob/v4/LICENSE.md>`_.

-------
Support
-------

Our developer support team is here to help you. You can find us on `Twitter <https://twitter.com/virgilsecurity>`_ and `email <support_>`_.

.. _support: mailto:support@virgilsecurity.com
.. _getstarted_root: https://developer.virgilsecurity.com/docs/python/get-started
.. _getstarted: https://developer.virgilsecurity.com/docs/python/guides
.. _getstarted_encryption: https://developer.virgilsecurity.com/docs/python/get-started/encrypted-communication
.. _getstarted_storage: https://developer.virgilsecurity.com/docs/python/get-started/encrypted-storage
.. _getstarted_data_integrity: https://developer.virgilsecurity.com/docs/python/get-started/data-integrity
.. _getstarted_passwordless_login: https://developer.virgilsecurity.com/docs/python/get-started/passwordless-authentication
.. _guides: https://developer.virgilsecurity.com/docs/python/guides
.. _guide_initialization: https://developer.virgilsecurity.com/docs/python/guides/settings/install-sdk
.. _guide_virgil_cards: https://developer.virgilsecurity.com/docs/python/guides/virgil-card/creating
.. _guide_virgil_keys: https://developer.virgilsecurity.com/docs/python/guides/virgil-key/generating
.. _guide_encryption: https://developer.virgilsecurity.com/docs/python/guides/encryption/encrypting
.. _initialize_root: https://developer.virgilsecurity.com/docs/python/guides/settings/initialize-sdk-on-client

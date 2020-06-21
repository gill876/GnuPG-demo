# GnuPG-demo
Implementation of GnuPG using python-gnupg.

### Usage
1. Create and activate python virtual environment.
```
$ python3 -m venv venv
$ source venv/bin/activate
```
2. Install requirements.
```
$ pip3 install -r requirements.txt
```
3. Run `flask_server.py` first in one terminal tab.
```
$ python3 flask_server.py
```
4. Then run `flask_client.py` in another terminal tab, while watching the previous
tab simultaneously.
```
$ python3 flask_client.py
```


### Resources
* [Server client socket connection](https://stackoverflow.com/a/57619742/10361668)
* [Gnu Privacy Guard how to](https://help.ubuntu.com/community/GnuPrivacyGuardHowto)
* [A Python wrapper for GnuPG](https://gnupg.readthedocs.io/en/latest/)
* [python-gnupg repository](https://bitbucket.org/vinay.sajip/python-gnupg/src/master/)
* [How To Verify Code and Encrypt Data with Python-GnuPG and Python 3](https://www.digitalocean.com/community/tutorials/how-to-verify-code-and-encrypt-data-with-python-gnupg-and-python-3)
* [GnuPG documentation](https://github.com/gpg/gnupg/tree/master/doc)
* [Check internet connectivity](https://stackoverflow.com/a/40283805/10361668)
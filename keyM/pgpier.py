#!/usr/bin/env python3
import os, socket
import gnupg
import uuid, hashlib

class Pgpier:

    def __init__(self, working_dir):
        self.wrk_dir = os.path.abspath(os.path.join(working_dir, os.pardir))
        self.gnupghome = working_dir
        self.gpg = gnupg.GPG(gnupghome=working_dir)
        self.gpg.encoding = 'utf-8' #sets encoding
        self.passphrase = None
        self.fingerprint = None
        self.keyid = None

    def key_pair(self, _name_email, _name_real, _name_comment="auto generated using gnupg.py", _key_type="RSA", _key_length=4096):
        #generate passphrase
        self.passphrase = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()
        #helper method to get key configuration
        input_data = self.gpg.gen_key_input(key_type=_key_type, key_length=_key_length, name_real=_name_real, name_comment=_name_comment, name_email=_name_email, passphrase=self.passphrase)
        #generation of key pair
        key = self.gpg.gen_key(input_data)
        self.fingerprint = key.fingerprint

    def set_passphrase(self, passphrase):
        self.passphrase = passphrase

    def list_pub_keys(self):
        public_keys = self.gpg.list_keys()
        return public_keys

    def exp_passphrase(self):
        #lists all files existing in a dir and checks if the file ends with the wrapper
        _path = self.wrk_dir
        _filename = self.fingerprint
        _wrapper = '(main)'
        _contents = self.passphrase

        file_names = [file for file in os.listdir(_path) if os.path.isfile(file) and file.endswith(_wrapper)]
        if file_names != []:
            for file in file_names:

                #removes the wrapper
                file_name_len = len(file)
                wrapper_len = len(_wrapper)
                file_nowrap = file_name_len - wrapper_len
                clean_f_name = file[0:file_nowrap]

                #clean file name
                clean_f = os.path.abspath(os.path.join(_path, clean_f_name))
                #implement so that if the file already exists it would make a copy
                try:
                    #renames the file without the wrapper
                    os.rename(file, clean_f)
                except Exception as e:
                    print(e)

        file = os.path.abspath(os.path.join(_path, '{0}{1}'.format(_filename, _wrapper)))
        with open('{}'.format(file), '{}'.format('w')) as f:
            f.write(_contents)
    

def is_connected():
    try:
        # connect to the host -- tells us if the host is actually
        # reachable
        socket.create_connection(("www.google.com", 80))
        return True
    except OSError:
        pass
        print("no connection")
    return False

def create_dir(dirname, override=False, path="/home"):
    """Creates directory in current working directory or custom path, if it does not exist
    Args:
        dirname (str): directory name
        override (bool): True, to enter a custome path where directory name would be created
        path (str): Custom path
    
    Returns:
        tuple (bool, directory path): (True, dir_path) if the directory exists or is created. (False, 'failed') if the process failed
    """
    success = False
    try:
        if override:
            #uses path from parameter
            dir_path = os.path.join(path, dirname)
            #creates directory if it does not exist
            if not os.path.exists(dir_path):
                os.mkdir(dir_path)
                success = True 
                return success, dir_path
            #success if directory already exists
            elif os.path.exists(dir_path):
                success = True
                return success, dir_path
            else:
                raise Exception

        #get current directory
        current_dir = os.getcwd()
        #create key directroy
        dir_folder = os.path.join(current_dir, dirname)

        #creates key folder if it does not exist
        if not os.path.exists(dir_folder):
            os.mkdir(dir_folder)
            success = True 
            return success, dir_folder
        #success if key file already exists
        elif os.path.exists(dir_folder):
            success = True
            return success, dir_folder
        else:
            raise Exception
    except Exception as e:
        print("Error:\n", e)
        return success, "failed"

def config_gpg(_path=False, gpg_dir=".gnupg"):
    """Creates the gpg instance
    Args:
        gpg_dir (str): directory name where gnupg uses

    Returns:
        GPG (obj): GPG Object
    """
    if _path is False:
        #retrieves home directory of current user
        home_dir = os.path.expanduser("~")
        
        #returns path of gnupg home directory and creates it if it does not exist
        result = create_dir(gpg_dir, override=True, path=home_dir)
        gpg_path = result[1]

    elif not (_path is False):
        result = create_dir(gpg_dir, override=True, path=_path)
        gpg_path = result[1]
    
    else:
        print('critical error')
        return None

    #instantiates GPG object
    gpg = gnupg.GPG(gnupghome=gpg_path)
    gpg.encoding = 'utf-8' #sets encoding
    return gpg
    ############Apparently, the passphrase passed without an issue. In the case it does not work, the following options below could work
    #create config file named `gpg-agent.conf` if it does not exits and add config
    #append the line `allow-loopback-pinentry` in the config file if the file already exists

def generate_key_pair(_name_email, _name_real, _name_comment="auto generated using gnupg.py", _key_type="RSA", _key_length=4096):

    #get gpg object
    gpg = config_gpg()

    #generate passphrase
    _passphrase = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()
    
    #helper method to get key configuration
    input_data = gpg.gen_key_input(key_type=_key_type, key_length=_key_length, name_real=_name_real, name_comment=_name_comment, name_email=_name_email, passphrase=_passphrase)

    #generation of key pair
    key = gpg.gen_key(input_data)

    return key, _passphrase

def show_keys():
    #get gpg object
    gpg = config_gpg()

    public_keys = gpg.list_keys()
    private_keys = gpg.list_keys(True)

    for key_item in public_keys:
        print("***Public Key***\n", key_item, "******\n")
    #print("public keys:\n", public_keys)
    #print("private keys:\n", private_keys)

def send_key(_keyid, _keyserver='keyserver.ubuntu.com'):
    #get gpg object
    gpg = config_gpg()

    if not is_connected():
        #cannot connect to the internet
        return None
    else:
        pass
    
    #Send key to keyserver
    try:
        result = gpg.send_keys(_keyserver, _keyid)
        print(result)
    except Exception as e:
        print("Key was not sent to server\n", e)

def receive_key(_keyid, _keyserver='keyserver.ubuntu.com'):
    #get gpg object
    gpg = config_gpg()

    if not is_connected():
        #cannot connect to the internet
        return None
    else:
        pass
    
    #Receive key from keyserver
    try:
        import_result = gpg.recv_keys(_keyserver, _keyid)
        fp_lst = [result['fingerprint'] for result in import_result.results]
        if len(fp_lst) >= 1:
            return fp_lst
        else:
            pass
    except Exception as e:
        print("Key was not received from server\n", e)
    return None

def delete_key(_finger_print, _private=False, _passphrase=None):
    #get gpg object
    gpg = config_gpg()

    if not _private:
        #attempts to public key delete key
        result = str(gpg.delete_keys(_finger_print))# same as gpg.delete_keys(fp, False) => public keys
    elif _private:
        result = str(gpg.delete_keys(_finger_print, True, passphrase=_passphrase))# True => private keys
    
    return result

#def exp_pub_key(_fingerprint)

def exp_passphrase(dir, file):
    with open('{}'.format(file), 'w') as f:
        pass

def encrypt_file(gpg, file_path, recipients, output):
    #file_path => path and filename
    #recipients => list of recipients
    #output => path and filename
    with open('{}'.format(file_path), '{}'.format('rb')) as file:
        encrypted_ascii_data = gpg.encrypt_file(file, recipients=recipients, output=output)
        return encrypted_ascii_data, encrypted_ascii_data.status

def decrypt_file(gpg, file_path, passphrase, output):
    with open('{}'.format(file_path), '{}'.format('rb')) as file:
        decrypted_data = gpg.decrypt_file(file, passphrase=passphrase, output=output)
        return decrypted_data, decrypted_data.status

def encrypt_data(gpg, data, recipients):
    encrypted_ascii_data = gpg.encrypt(data, recipients=recipients)
    return encrypted_ascii_data #str() => to get ascii

def decrypt_data(gpg, data, passphrase):
    decrypted_data = gpg.decrypt(data, passphrase=passphrase)
    return decrypted_data
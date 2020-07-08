#!/usr/bin/env python3
import socket
import gnupg
import uuid, hashlib, os, random, string

class Pgpier:
    """A class that handles encryption and decryption using the python-gnupg module
    """

    def __init__(self, working_dir):
        """The Pgpier class will instantiate with the working directory that also has a parent directory

        Args:
            working_dir (str): The path to the .gnupg directory where GnuPG files will be stored
                               with a parent directory where this class will store and handle pertinent
                               data

        Returns:
            None
        """
        self.wrk_dir = os.path.abspath(os.path.join(working_dir, os.pardir)) #gets the parent of the working directory
        self.gnupghome = working_dir
        self.gpg = gnupg.GPG(gnupghome=working_dir) # , options=['--pinentry-mode=loopback']
        self.gpg.encoding = 'utf-8' #sets encoding
        self.passphrase = None
        self.fingerprint = None
        self.keyid = None

    def key_pair(self, _name_email, _name_real, _name_comment="auto generated using gnupg.py", _key_type="RSA", _key_length=4096):
        """The generation of the private public key pairs

        Args:
            _name_email (str): Email of the user
            _name_real (str): Full name of the user
            _name_comment (str): Optional comment for the user
            _key_type (str): The key type of the private public key pair
            _key_length (int): Key length of the private public key pair

        Returns:
            None
        """
        #generates random passphrase
        self.passphrase = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()
        #helper method to get key configuration
        input_data = self.gpg.gen_key_input(key_type=_key_type, key_length=_key_length, name_real=_name_real, name_comment=_name_comment, name_email=_name_email, passphrase=self.passphrase)
        #generation of key pair
        key = self.gpg.gen_key(input_data)
        #print("stderr: ", key.stderr)
        self.fingerprint = key.fingerprint #store fingerprint in class

    def set_passphrase(self, passphrase):
        """Method to set the passphrase in the class

        Args:
            passphrase (str): Passphrase to store in class

        Returns:
            None
        """
        self.passphrase = passphrase

    def set_fingerprint(self, fingerprint):
        """Method to set fingerprint in the class

        Args:
            fingerprint (str): Fingerprint of the public private key pair

        Returns:
            None
        """
        self.fingerprint = fingerprint

    def set_keyid(self):
        """Method to set keyid by retrieving all keys stored in the GnuPG keyring and retrieve
        the keyid associated with the main public private key pair

        Args:
            None

        Returns:
            None
        """
        
        keys = self.list_pub_keys()
        fingerprint = self.fingerprint

        if keys != []:
            for key in keys:
                if key['fingerprint'] == fingerprint:
                    self.keyid = key['keyid']#set keyid associated with fingerprint in class
        else:
            pass

    def list_pub_keys(self):
        """Method to list all the public keys stored in the GnuPG keyring

        Args:
            None
        
        Returns:
            list: List of dictionaries of each public key stored
        """
        public_keys = self.gpg.list_keys()
        return public_keys

    def exp_main(self, _wrapper='(main)'):
        """Method to store the passphrase for future retrieval and name the file by the fingerprint of the 
        class. The method also adds a wrapper to the name of the file so that when the Pgpier class is looking
        for the public private key pair, it finds the pair it owns

        Args:
            _wrapper (str): The name of the wrapper

        Returns:
            None
        """
        #lists all files existing in a dir and checks if the file ends with the wrapper
        _path = self.wrk_dir
        _filename = self.fingerprint
        #_wrapper = '(main)'
        _contents = self.passphrase

        file_names = [f for f in os.listdir(_path) if os.path.isfile(f) and f.endswith(_wrapper)]
        if file_names != []:
            for f in file_names:

                #removes the wrapper
                file_name_len = len(f)
                wrapper_len = len(_wrapper)
                file_nowrap = file_name_len - wrapper_len
                clean_f_name = f[0:file_nowrap]

                #clean file name
                clean_f = os.path.abspath(os.path.join(_path, clean_f_name))
                #implement so that if the file already exists it would make a copy
                try:
                    #renames the file without the wrapper
                    os.rename(f, clean_f)
                except Exception as e:
                    print(e)

        _file = os.path.abspath(os.path.join(_path, '{0}{1}'.format(_filename, _wrapper)))
        with open('{}'.format(_file), '{}'.format('w')) as f:
            f.write(_contents)

    def imp_main(self, _wrapper='(main)'):
        """Method to import the fingerprint and passphrase of the owned public private key pair of the
        user. The method also looks for a wrapper on the file to distinguish the public private key 
        pair the user currently owns. 

        Args:
            _wrapper (str): The name of the wrapper

        Returns:
            tuple: String of fingerprint and string of passphrase if it finds the public private key pairs
            the user currently owns
            
            None: If there are no public private key pair the user currently owns
        """

        _path = self.wrk_dir #path to parent directory of gnupg home, where Pgpier will operate its own files
        #_wrapper = '(main)'

        key = [_file for _file in os.listdir(_path) if _file.endswith(_wrapper)] #returns list of files if it ends with the wrapper

        key_len = len(key)
        if key_len > 1:
            raise Exception("critical error - 0: more than one main keys\nreport issue")
        
        elif key_len == 1:
            _fingerprint = key[0]

            #removes the wrapper
            file_name_len = len(_fingerprint)
            wrapper_len = len(_wrapper)
            file_nowrap = file_name_len - wrapper_len
            clean_fp = _fingerprint[0:file_nowrap]

            fp_file = os.path.abspath(os.path.join(_path, _fingerprint))

            with open('{}'.format(fp_file), '{}'.format('r')) as f:
                _passphrase = f.read()
            
            if type(_passphrase) != str:
                raise Exception("critical error - 1: error reading for passphrase\nreport issue")

            return clean_fp, _passphrase
        
        else:
            return None
    
    def set_from_imp(self, wrapper='(main)'):
        """Method to get the fingerprint and passphrase the user currently owns and then
        assign those values inside the class to utilize the user's public private key pair

        Args:
            None

        Returns:
            True: If it retrieved the fingerprint and passphrase from a file
            False: If it did not retrieve anything
        """
        result = None
        try:
            result = self.imp_main(wrapper)
        except Exception as e:
            print(e)

        if result != None:
            self.set_fingerprint(result[0]) 
            self.set_passphrase(result[1])
        
        success = True if result != None else False
        return success

    def exp_pub_key(self):
        """Method to export the user's public key into ASCII

        Args:
            None

        Returns:
            str: String of ASCII armored public key
        """
        ascii_armored_public_keys = None
        keyid = self.keyid
        gpg = self.gpg

        if keyid != None:
            ascii_armored_public_keys = gpg.export_keys(keyid)
            return ascii_armored_public_keys
        else:
            return ascii_armored_public_keys

    def imp_pub_key(self, key_data):
        """Method to import the ASCII public of a user into the current user's GnuPG keyring

        Args:
            key_data (str): String of public key armored ASCII

        Returns:
            None
        """
        gpg = self.gpg
        
        import_result = gpg.import_keys(key_data)

    def pub_file(self):
        """Method to export the armored ASCII public key into an asc file

        Args:
            None

        Returns:
            None
        """
        
        pub_key = self.exp_pub_key()
        fingerprint = self.fingerprint
        path = self.wrk_dir

        pub_file = os.path.abspath(os.path.join(path, fingerprint)) #export to parent directory of gnupg home

        if pub_key != None: #checks that the class' public key was exported
            with open('{0}{1}'.format(pub_file, '.asc'), '{}'.format('w')) as f:
                f.write(pub_key)

    def sym_encrypt_files(self, symmetric_key, file_path, output, delaf=False, algorithm='AES256', armor=True):
        """Method to encrypt files using a symmetric key

        Args:
            symmetric_key (str): String of passphrase to be used to encrypt the data
            file_path (str): Absolute file path to the files to be encrypted
            output (str): Absolute file path to intended file output
            delaf (bool): True if the files should be deleted after encryption
                          Fasle if the files should be kept after encryption
            algorithm (str): The type of algorithm to be used to encrypt the data
            armor (bool): True for the return type to be in ASCII string
                          False for the return type to be Crypt object

        Returns:
            None
        """
        gpg = self.gpg

        files_dir = []

        files = [f for f in os.listdir(file_path)]
        
        for f in files:
            files_dir.append('{}'.format(f))

        for x in files_dir:
            with open('{}{}{}'.format(file_path, os.sep, x), '{}'.format('r')) as f:
                contents = f.read()
                crypt = gpg.encrypt(contents, symmetric=algorithm, passphrase=symmetric_key, armor=armor, recipients=None, output='{}{}{}'.format(file_path, os.sep, files_dir[files_dir.index(x)]))
                #print("ok: ", crypt.ok)
                #print("status: ", crypt.status)
                #print("stderr: ", crypt.stderr)
            if delaf:
                os.rename('{}{}{}'.format(file_path, os.sep, files_dir[files_dir.index(x)]), '{}{}{}'.format(output, os.sep, files_dir[files_dir.index(x)]))

    def encrypt_data(self, data, recipients):
        """Method to encrypt data using the imported recipient's public key from user's GnuPG keyring

        Args:
            data (str): Data to be encrypted
            recipients (int): Fingerprint of recipient

        Returns:
            str: encrypted data in ASCII string
        """
        gpg = self.gpg

        encrypted_ascii_data = gpg.encrypt(data, recipients=recipients)
        #print(encrypted_ascii_data.status)
        ascii_str = str(encrypted_ascii_data)
        return ascii_str

    def sym_decrypt_files(self, symmetric_key, file_path, output, delaf=False):
        """Method to decrypt files using a symmetric key

        Args:
            symmetric_key (str): String of passphrase to be used to decrypt the data
            file_path (str): Absolute file path to the files to be encrypted
            output (str): Absolute file path to intended file output
            delaf (bool): True if the files should be deleted after decryption
                          Fasle if the files should be kept after decryption
            algorithm (str): The type of algorithm that was used to encrypt the data
            armor (bool): True for the return type to be in ASCII string
                          False for the return type to be Crypt object

        Returns:
            None
        """
        gpg = self.gpg

        files_dir = []

        files = [f for f in os.listdir(file_path)]
        
        for f in files:
            files_dir.append('{}'.format(f))

        for x in files_dir:
            with open('{}{}{}'.format(file_path, os.sep, x), '{}'.format('r')) as f:
                crypt = f.read()
                #print(crypt)
                data = gpg.decrypt(crypt, passphrase=symmetric_key)
                de_data = (data.data).decode('utf-8')
                #print('\n\n\n\n--->{}<---\n\n\n'.format(de_data))
                with open('{}{}{}'.format(output, os.sep, files_dir[files_dir.index(x)]), '{}'.format('w')) as decrypted:
                    decrypted.write(de_data)
                #print("ok: ", data.ok)
                #print("status: ", data.status)
                #print("stderr: ", data.stderr)
            if delaf:
                os.remove('{}{}{}'.format(file_path, os.sep, x))    
    def decrypt_data(self, data, passphrase):
        """Method to decrypt data using the imported recipient's public key from user's GnuPG keyring

        Args:
            data (str): Data in String ASCII to be decrypted
            passphrase (str): Passphrase of the user

        Returns:
            str: Decrypted data into string
        """
        gpg = self.gpg
        passphrase = self.passphrase

        decrypted_data = gpg.decrypt(data, passphrase=passphrase)

        data = (decrypted_data.data).decode('utf-8')
        return data

    def email_to_key(self, email):
        """Method to retrieve fingerprint of associated email address from the GnuPG keyring

        Args:
            email (str): Email address

        Returns:
            int: Fingerprint that is associated with the email address if it is found
            None: If no associated fingerprint is found
        """
        gpg = self.gpg
        # Gets all available public keys in keyring
        keys = self.list_pub_keys()

        result = None

        for key in keys: # Go through each public key
            uids = list(filter((lambda item: email in item), key['uids']))
            if uids != []:
                parts = uids[0].split(' ')
                wrapped_email = list(filter((lambda item: '<' in item), parts))
                unwrapped_email = wrapped_email[0].strip('<>')
                if unwrapped_email == email:
                    return key['fingerprint']
        
        return result
    
    def trust_key(self, fingerprint, trustlevel='TRUST_ULTIMATE'):
        """Method to trust public key that was imported to have the ability to encrypt data using
        that public key

        Args:
            fingerprint (int): Fingerprint of pubic key to trust
            trustlevel (str): Trust level to assign to public key

        Returns:
            None
        """
        gpg = self.gpg

        gpg.trust_keys(fingerprint, trustlevel)

    def symmetric_encrypt(self, data, passphrase, algorithm='AES256', armor=True):
        """Method to encrypt data using symmmetric key encryption using a passphrase and encryption 
        algorithm

        Args:
            data (str): String of data to be encrypted
            passphrase (str): String of passphrase to be used to encrypt the data
            algorithm (str): The type of algorithm to be used to encrypte the data
            armor (bool): True for the return type to be in ASCII string
                          False for the return type to be Crypt object

        Returns:
            str: ASCII string of encrypted data
        """
        gpg = self.gpg

        crypt = gpg.encrypt(data, symmetric=algorithm, passphrase=passphrase, armor=armor, recipients=None)
        #print(crypt.status)
        return str(crypt)

    def symmetric_decrypt(self, data, passphrase):
        """Method to decrypt data that was encrypted using symmetric encryption

        Args:
            data (str): Data in ASCII string to be decrypted
            passphrase (str): Passphrase used in the encryption
        
        Returns:
            str: ASCII string of decrypted data
        """
        gpg = self.gpg

        data = gpg.decrypt(data, passphrase=passphrase)
        #print(data.status)
        return (data.data).decode('utf-8')
    
    def gen_symm_key(self, stringLength=70):
        password_characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(password_characters) for i in range(stringLength))
    
    def _TEST_ONLY_delete_key(self):
        self.gpg.delete_keys(self.fingerprint, True, passphrase=self.passphrase)
        self.gpg.delete_keys(self.fingerprint)


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

#gpg = Pgpier('/home/cargill/Documents/GnuPG-demo/keys/.gnupg')
#gpg.set_from_imp()
#print(gpg.fingerprint)
#print(gpg.passphrase)
#gpg.set_keyid()
#print(gpg.keyid)
#print(gpg.list_pub_keys())
#pubkey = gpg.exp_pub_key()
#print(pubkey)
#gpg.pub_file()
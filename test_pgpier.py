#!/usr/bin/env python3

# Standard imports
import unittest, os, sys, uuid, hashlib, random, string, shutil, stat, tempfile

# PIP imports
import gnupg

# Module import
import keyM.pgpier as pgp

class TestEncrypt(unittest.TestCase):
    """Test all methods of Pgpier class
    """

    @classmethod
    def setUpClass(cls):
        print('setupClass\n\n')

        ######################Essential######################
        main_dir = os.path.abspath(
            os.path.join(
                os.getcwd(), '{}'.format('keys')
            )
        )
        
        cls.main_dir = main_dir
        ####################################################
        
        ######################1st Pgpier######################
        # Create sub directory for 1st Pgpier and change permissions for the directory
        test1 = os.path.join(main_dir, '{}'.format('test1'))
        cls.test1 = test1
        person1 = os.path.join(test1, '{}'.format('.gnupg'))
        os.makedirs(person1)
        os.chmod(person1, stat.S_IRWXU)

        # Create Pgpier class
        gpg1 = pgp.Pgpier(person1)

        # Variables for 1st key pair generation
        wrapper1 = '(Person1)'
        cls.wrapper1 = wrapper1
        person1_name = 'John Brown'
        person1_email = 'john_brown_2020_test@gmail.com'
        person1_comment = 'Unit testing with person1'

        # Checks if a passphrase has been exported already
        result1 = gpg1.set_from_imp(wrapper1)

        if not result1: # If passphrase has not been export, a new key pair will be generated
            gpg1.key_pair(person1_email, person1_name, person1_comment)
            gpg1.exp_main(wrapper1)
            cls.gpg1 = gpg1
        
        print("***\nPerson1 Pgpier directory and key pair generated in: ", person1,
            "\nName: ", person1_name, "\nEmail: ", person1_email,
            "\nComment: ", person1_comment, "\n***"
        )
        
        ####################################################

        ######################2nd Pgpier######################
        # Create sub directory for 2nd Pgpier and change permissions for the directory
        test2 = os.path.join(main_dir, '{}'.format('test2'))
        cls.test2 = test2
        person2 = os.path.join(test2, '{}'.format('.gnupg'))
        os.makedirs(person2)
        os.chmod(person2, stat.S_IRWXU)

        # Create Pgpier class
        gpg2 = pgp.Pgpier(person2)
        
        wrapper2 = '(Person2)'
        cls.wrapper2 = wrapper2
        person2_name = 'Mary Jane'
        person2_email = 'mary_jane_2020_test@gmail.com'
        person2_comment = 'Unit testing with person2'

        # Checks if a passphrase has been exported already
        result2 = gpg2.set_from_imp(wrapper2)

        if not result2: # If passphrase has not been export, a new key pair will be generated
            gpg2.key_pair(person2_email, person2_name, person2_comment)
            gpg2.exp_main(wrapper2)
            cls.gpg2 = gpg2
        print("***\nPerson2 Pgpier directory and key pair generated in: ", person2,
            "\nName: ", person2_name, "\nEmail: ", person2_email,
            "\nComment: ", person2_comment, "\n***"
        )
        ####################################################

    @classmethod
    def tearDownClass(cls):
        print('teardownClass')
        print('Removing Pgpier main directory: ', cls.main_dir)
        shutil.rmtree(cls.main_dir)

    def setUp(self):
        print('setUp')

        self.gpg1 = self.__class__.gpg1
        self.gpg2 = self.__class__.gpg2

        self.test1_dir = self.__class__.test1
        self.test2_dir = self.__class__.test2

        self.wrapper1 = self.__class__.wrapper1
        self.wrapper2 = self.__class__.wrapper2

    def tearDown(self):
        print('tearDown\n')

    def test_key_generation(self):
        """Checks if both Pgpier instances generated their key pairs
        """
        print("***Key generation test***")
        key_gen1 = False
        key_gen2 = False

        if self.gpg1.fingerprint != '':
            key_gen1 = True

        if self.gpg2.fingerprint != '':
            key_gen2 = True

        keys1 = self.gpg1.list_pub_keys()
        keys2 = self.gpg2.list_pub_keys()

        person1_key = False
        person2_key = False
        if keys1 != []:
            for key in keys1:
                if key['uids'] == ['John Brown (Unit testing with person1) <john_brown_2020_test@gmail.com>']:
                    person1_key = True
        
        if keys2 != []:
            for key in keys2:
                if key['uids'] == ['Mary Jane (Unit testing with person2) <mary_jane_2020_test@gmail.com>']:
                    person2_key = True

        self.assertTrue(person1_key)
        self.assertTrue(person2_key)
        
        self.assertTrue(key_gen1)
        self.assertTrue(key_gen2)
        
    def test_set_passphrase(self):
        print("***Set passphrase test***")

        prev_passphrase1 = self.gpg1.passphrase
        prev_passphrase2 = self.gpg2.passphrase

        print('Previous passphrase for 1st Pgpier: {}'.format(prev_passphrase1))
        print('Previous passphrase for 2nd Pgpier: {}'.format(prev_passphrase2))

        next_passphrase1 = 'password-123'
        next_passphrase2 = 'password-abc'

        print('Next passphrase for 1st Pgpier: {}'.format(next_passphrase1))
        print('Next passphrase for 2nd Pgpier: {}'.format(next_passphrase2))

        self.gpg1.set_passphrase(next_passphrase1)
        self.gpg2.set_passphrase(next_passphrase2)

        set_passphrase1 = self.gpg1.passphrase
        set_passphrase2 = self.gpg2.passphrase

        print('Set passphrase for 1st Pgpier: {}'.format(set_passphrase1))
        print('Set passphrase for 2nd Pgpier: {}'.format(set_passphrase2))

        self.assertEqual(set_passphrase1, next_passphrase1)
        self.assertEqual(set_passphrase2, next_passphrase2)

        print("Restoring previous passphrase...")
        self.gpg1.set_passphrase(prev_passphrase1)
        self.gpg2.set_passphrase(prev_passphrase2)

        set_passphrase1 = self.gpg1.passphrase
        set_passphrase2 = self.gpg2.passphrase

        self.assertEqual(set_passphrase1, prev_passphrase1)
        self.assertEqual(set_passphrase2, prev_passphrase2)

    def test_set_keyid(self):
        print("***Set keyid test***")

        self.gpg1.set_keyid()
        self.gpg2.set_keyid()

        keyid1 = self.gpg1.keyid
        keyid2 = self.gpg2.keyid

        print('Key id for 1st Pgpier: {}'.format(keyid1))
        print('Key id for 2nd Pgpier: {}'.format(keyid2))

        self.assertIsNotNone(keyid1)
        self.assertIsNotNone(keyid2)

    def test_list_pub_keys(self):
        print("***List public keys test***")

        keys_lst1 = self.gpg1.list_pub_keys()
        keys_lst2 = self.gpg2.list_pub_keys()

        is_keys_lst1 = False
        is_keys_lst2 = False

        if keys_lst1 != []:
            is_keys_lst1 = True
            print("Keys in 1st:\n")
            for key in keys_lst1:
                print('\n--->{}<---\n'.format(key))

        if keys_lst2 != []:
            is_keys_lst2 = True
            print("Keys in 2nd:\n")
            for key in keys_lst2:
                print('\n--->{}<---\n'.format(key))

        self.assertTrue(is_keys_lst1)
        self.assertTrue(is_keys_lst2)

    def test_exp_main(self):
        print("***Export main test***")

        pass_result1 = False
        pass_result2 = False
        
        wrapper1 = '(ExportTest_1)'
        wrapper2 = '(ExportTest_2)'

        fingerprint1 = self.gpg1.fingerprint
        fingerprint2 = self.gpg2.fingerprint
        passphrase1 = self.gpg1.passphrase
        passphrase2 = self.gpg2.passphrase

        self.gpg1.exp_main(wrapper1)
        self.gpg2.exp_main(wrapper2)

        files1 = [f for f in os.listdir(self.test1_dir) if f.endswith(wrapper1) and fingerprint1 in f]
        files2 = [f for f in os.listdir(self.test2_dir) if f.endswith(wrapper2) and fingerprint2 in f]
        
        if files1 != [] and files2 != []:
            print('\n1st file: {}\n2nd file: {}'.format(files1, files2))
            
            with open('{}{}{}'.format(self.test1_dir, os.sep, files1[0]), '{}'.format('r')) as f1:
                contents1 = f1.read()
                print('\n\n1st fingerprint: {}'.format(fingerprint1))
                print('1st contents: {}'.format(contents1))
                print('1st passphrase: {}'.format(passphrase1))
                if contents1 == passphrase1:
                    pass_result1 = True
            
            with open('{}{}{}'.format(self.test2_dir, os.sep, files2[0]), '{}'.format('r')) as f2:
                contents2 = f2.read()
                print('\n\n2nd fingerprint: {}'.format(fingerprint2))
                print('2nd contents: {}'.format(contents2))
                print('2nd passphrase: {}'.format(passphrase2))
                if contents2 == passphrase2:
                    pass_result2 = True
        
        self.assertTrue(pass_result1)
        self.assertTrue(pass_result2)

    def test_set_from_imp(self):
        print("Set from import and import main test")

        print('1st Pgpier wrapper: {}\n2nd Pgpier wrapper: {}'.format(self.wrapper1, self.wrapper2))
        result1 = self.gpg1.set_from_imp(self.wrapper1)
        result2 = self.gpg2.set_from_imp(self.wrapper2)

        self.assertTrue(result1)
        self.assertTrue(result2)
    
if __name__ == '__main__':
    unittest.main()
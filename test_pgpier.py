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
        person1 = os.path.join(test1, '{}'.format('.gnupg'))
        os.makedirs(person1)
        os.chmod(person1, stat.S_IRWXU)

        # Create Pgpier class
        gpg1 = pgp.Pgpier(person1)

        # Variables for 1st key pair generation
        wrapper1 = '(Person1)'
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
        person2 = os.path.join(test2, '{}'.format('.gnupg'))
        os.makedirs(person2)
        os.chmod(person2, stat.S_IRWXU)

        # Create Pgpier class
        gpg2 = pgp.Pgpier(person2)
        
        wrapper2 = '(Person2)'
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

    def tearDown(self):
        print('tearDown\n')

    def test_key_generation(self):
        """Checks if both Pgpier instances generated their key pairs
        """
        print("Key generation test")
        key_gen1 = False
        key_gen2 = False

        if self.gpg1.fingerprint != '':
            key_gen1 = True

        if self.gpg2.fingerprint != '':
            key_gen2 = True
        
        self.assertTrue(key_gen1)
        self.assertTrue(key_gen2)
        
    def test_set_passphrase(self):
        print("Set passphrase test")

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

    
if __name__ == '__main__':
    unittest.main()
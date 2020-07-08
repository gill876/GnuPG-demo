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
        test1 = os.path.join(main_dir, '{}'.format('test1'))
        person1 = os.path.join(test1, '{}'.format('.gnupg'))
        os.makedirs(person1)
        os.chmod(person1, stat.S_IRWXU)

        gpg1 = pgp.Pgpier(person1)

        wrapper1 = '(Person1)'
        person1_name = 'John Brown'
        person1_email = 'john_brown_2020_test@gmail.com'
        person1_comment = 'Unit testing with person1'

        result1 = gpg1.set_from_imp(wrapper1)

        if not result1:
            gpg1.key_pair(person1_email, person1_name, person1_comment)
            gpg1.exp_main(wrapper1)
            cls.gpg1 = gpg1
        
        print("***\nPerson1 Pgpier directory and key pair generated in: ", person1,
            "\nName: ", person1_name, "\nEmail: ", person1_email,
            "\nComment: ", person1_comment, "\n***"
        )
        
        ####################################################

        ######################2nd Pgpier######################
        
        """ person2 = os.path.join(main_dir2, '{}'.format('.gnupg'))
        os.mkdir(person2)
        cls.person2 = person2
        gpg2 = Pgpier(person2)
        
        wrapper2 = '(Person2)'
        person2_name = 'Mary Jane'
        person2_email = 'mary_jane_2020_test@gmail.com'
        person2_comment = 'Unit testing with person2'

        result2 = gpg2.set_from_imp(wrapper2)

        if not result2:
            gpg2.key_pair(person2_email, person2_name, person2_comment)
            gpg2.exp_main(wrapper2)
            cls.gpg2 = gpg2
        print("***\nPerson2 Pgpier directory and key pair generated in: ", person2,
            "\nName: ", person2_name, "\nEmail: ", person2_email,
            "\nComment: ", person2_comment, "\n***"
        ) """
    

    @classmethod
    def tearDownClass(cls):
        print('teardownClass')
        print('Removing Person1 Pgpier directory: ', cls.main_dir)
        shutil.rmtree(cls.main_dir)

    def setUp(self):
        print('setUp')

        print('Retrieve person1 gpg object')
        self.gpg1 = self.__class__.gpg1
        print(self.gpg1.list_pub_keys())

        """ print('Retrieve person2 gpg object')
        self.gpg2 = self.__class__.gpg2 """

    def tearDown(self):
        print('tearDown\n')

    def test_example(self):
        with tempfile.TemporaryDirectory() as tmpdirname:
            print('created temporary directory', tmpdirname)
        print(self.gpg1.keyid)
    
if __name__ == '__main__':
    unittest.main()
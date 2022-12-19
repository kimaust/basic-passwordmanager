import os
import json
import binascii

from pathlib import Path
from getpass import getpass
from Crypto.Cipher import AES
from tabulate import tabulate

import scrypt


class PasswordManager():
    ENCODING = "utf-8"  # Encoding used. UTF-16 can be used as well.
    # The filename of the file that contains JSON data.
    DATA_FILENAME = "data.json"

    def __init__(self):
        self.data = {"websites": {}}  # Dict for storing the JSON data.

        # The pin number used to decrypt the stored AES message.
        self.pin = None

        # Supported options.
        self.options = {
            "funcs": [self.__find_credential, self.__add_website, self.__exit],
            "descriptions": ["Find Credential", "Add Website", "Exit"]
        }

        # Whether the program should exit.
        self.is_done = False

    def start(self):
        # Get the pin from the user.
        self.pin = self.__ask_pin()

        # Read the JSON data or create one if none.
        succeed = self.__read_data()
        if not succeed:
            return

        # Start the password manager.
        option = -1
        while not self.is_done:
            # Display registered websites.
            self.__display_websites()

            # Display available options and get input.
            self.__display_options()
            user_input = input("Select an option: ")
            try:
                option = int(user_input)
            except ValueError:
                # Invalid input type, skip to next loop to ask for new input.
                print(f"Invalid input: {user_input}.")
                continue

            # Check for the range to see if it's one of available options.
            if not (1 <= option <= (len(self.options) + 1)):
                print(f"Invalid option: {option}")
            else:
                # Valid option: get the associated function and execute that.
                func = self.options["funcs"][option-1]
                func()

    def __write_data(self):
        """Writing JSON data (`self.data`) from the given file.

        Returns:
            bool: True if write successfully and false otherwise.
        """
        try:
            with open(PasswordManager.DATA_FILENAME, "w") as file:
                json.dump(self.data, file, indent=4)
        except IOError as msg:
            print(
                f"Failed to open the {PasswordManager.DATA_FILENAME} file. Error: {msg}")
            return False

        return True

    def __read_data(self):
        """Reading JSON data from the given file.

        Returns:
            bool: True if read successfully and false otherwise.
        """
        path = Path(PasswordManager.DATA_FILENAME)
        if not path.is_file():
            self.__write_data()
        else:
            try:
                with open(PasswordManager.DATA_FILENAME, "r") as file:
                    self.data = json.load(file)
            except IOError as msg:
                print(
                    f"Failed to open the {PasswordManager.DATA_FILENAME} file. Error: {msg}")
                return False

        return True

    def __exit(self):
        self.is_done = True

    def __ask_pin(self):
        """Asks the user for the pin number.
        """
        return getpass("Please enter the pin: ")

    def __display_options(self):
        """Builds option text for display.

        Returns:
            str: Tabulated option text display.
        """
        option_text = []
        for pos, desc in enumerate(self.options["descriptions"], start=1):
            option_text.append(f"{pos}. {desc}")

        print(tabulate([["\n".join(option_text)]], tablefmt="grid"))

    def __display_websites(self):
        """Displays registered websites to the user.
        """
        display_list = []
        for pos, website in enumerate(self.data["websites"].keys(), start=1):
            display_list.append(f"{pos}. [{website}]")

        table = [["\n".join(display_list)]]
        print(tabulate(table, tablefmt="grid"))

    def __encrypt(self, msg, password):
        """Encrypts the message using the given password (pin) using AES-256.

        Reference: https://cryptobook.nakov.com/symmetric-key-ciphers/aes-encrypt-decrypt-examples
        """
        kdf_salt = os.urandom(16)
        secret_key = scrypt.hash(
            password, kdf_salt, N=16384, r=8, p=1, buflen=32)
        aes_cipher = AES.new(secret_key, AES.MODE_GCM)
        ciphertext, auth_tag = aes_cipher.encrypt_and_digest(msg)
        return (kdf_salt, ciphertext, aes_cipher.nonce, auth_tag)

    def __decrypt(self, encrypted_msg, password):
        """Decrypts the encrypted (via AES-256) message using the given password (pin).

        Reference: https://cryptobook.nakov.com/symmetric-key-ciphers/aes-encrypt-decrypt-examples
        """
        (kdf_salt, ciphertext, nonce, auth_tag) = encrypted_msg
        secret_key = scrypt.hash(
            password, kdf_salt, N=16384, r=8, p=1, buflen=32)
        aes_cipher = AES.new(secret_key, AES.MODE_GCM, nonce)
        plaintext = aes_cipher.decrypt_and_verify(ciphertext, auth_tag)
        return plaintext

    def __find_credential(self):
        """Displays the credential for the given website that user has entered if available.
        """
        website_name = input("Enter the name of the website: ")

        # Get the website credential JSON details.
        website_credential = self.data["websites"].get(website_name)

        # Couldn't find the website with the given name.
        if not website_credential:
            print(f"Unknown website: {website_name}")
            return

        # Get the email and encrypted message which stores password.
        email = website_credential["email"]
        encrypted_msg = website_credential["msg"]

        # Encode the encrypted data back to bytes and unhex it.
        encoded_msg = tuple(
            [binascii.unhexlify(data.encode(PasswordManager.ENCODING)) for data in encrypted_msg])
        encoded_pin = self.pin.encode(PasswordManager.ENCODING)

        # Attempt to decrypt the message using the given pin.
        try:
            decrypted_msg = self.__decrypt(encoded_msg, encoded_pin)
        except ValueError:
            print(f"{self.pin} is invalid pin! Failed to retrieve the password.")
            return

        # Display the e-mail and password for it in tabular manner.
        password = decrypted_msg.decode(PasswordManager.ENCODING)
        credential_display_text = f"Email: {email}\nPassword: {password}"
        table = [[credential_display_text]]
        print(tabulate(table, tablefmt="grid"))

    def __add_website(self):
        """Adds a new website and write to JSON file.
        """
        # TODO: Support username.
        website_name = input("Enter the name of the website: ").strip()
        website_email = input("Enter the email for this website: ")
        website_password = getpass("Enter the password for this website: ")

        # Encode the pin and password into bytes, and encrypt it using AES-256.
        pin = self.pin.encode(PasswordManager.ENCODING)
        password = website_password.encode(PasswordManager.ENCODING)
        encrypted_msg = self.__encrypt(password, pin)

        # Add a new entry to the JSON file for this new website.
        # Since `json` cannot dump bytes, it is hexified and then converted into string using utf-8 encoding.
        self.data["websites"][website_name] = {
            "email": website_email,
            "msg": [binascii.hexlify(data).decode(PasswordManager.ENCODING) for data in encrypted_msg]
        }
        # TODO: Use append instead of truncating everything.
        # Write the new JSON data.
        self.__write_data()

        # Decrypt again for assertion purpose to verify that it is done correctly.
        decrypted_msg = self.__decrypt(encrypted_msg, pin)
        assert website_password == decrypted_msg.decode(
            PasswordManager.ENCODING)

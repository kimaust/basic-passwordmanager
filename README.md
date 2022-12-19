# Password Manager
This is a very basic CLI password manager. 

It enables you to add a website by providing the name of the website, email, and password, which are then stored in a JSON file. These credentials can be retrieved by searching for the website by name. The password is encrypted using AES-256, and the initial pin number you enter is used for encryption and decryption.

## How to Use
1. Install the dependencies using the following command:

`pip install -r requirements.txt`

2. Execute the password manager via:

`python main.py`

## Note
If you are using Windows and encounter an error while attempting to install the scrypt package, you will need to install [OpenSSL](https://slproweb.com/products/Win32OpenSSL.html). For more information, refer to the [scrypt](https://pypi.org/project/scrypt/) documentation.
# Test keys
The keys in this folder are test keys:
`private_keys_jwt.txt` lists the private key(s) corresponding to the public key in `public_keys_jwt.txt`. In this file, the key listed on the line number defined by `UNIT_TEST_PUBLIC_KEY_JWT_KEY_INDEX` is used for testing in the test_mfl_license_check test.

(Re-)generate the jwt keys for testing by running this:
```bash
(
    set -e
    openssl genrsa -out "private_key_jwt.pem" 4096
    openssl rsa -pubout -in "private_key_jwt.pem" -out "public_key_jwt.pem"
    echo private_key_jwt.pem > private_keys_jwt.txt 
    echo public_key_jwt.pem > public_keys_jwt.txt 
    python3 -c 'import uuid; print(uuid.uuid4())' > public_keys_jwt_key_id.txt 
)
```
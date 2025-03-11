import argparse
import os
import json
from pathlib import Path
import subprocess




def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cmake-source-dir', 
                        required=True)
    parser.add_argument('--jansson-library-dir', 
                        required=True)
    args = parser.parse_args()
    cmake_source_dir=args.cmake_source_dir
    jansson_library_dir=args.jansson_library_dir

    WELLKNOWN_URL_JSON_FILE = f"{cmake_source_dir}/wellknown_url.json"
    with open(WELLKNOWN_URL_JSON_FILE, encoding='utf-8') as f:
        JWKS_JSON_FILE_URL = json.load(f)["JWKS_JSON_FILE_URL"]
    JWKS_JSON_FILE_FILENAME = JWKS_JSON_FILE_URL.rsplit("/", maxsplit=1)[-1]
    JWKS_JSON_FILE = f"{cmake_source_dir}/{JWKS_JSON_FILE_FILENAME}"
    JWT_KEYS_DIR = f"{cmake_source_dir}/jwt_keys"

    print(f"Updating jwt keys from {JWKS_JSON_FILE_URL}")
    subprocess.check_output(["curl","-L",JWKS_JSON_FILE_URL,"--output",JWKS_JSON_FILE])
    subprocess.check_output(["rm","-rf", JWT_KEYS_DIR])
    subprocess.check_output(["mkdir","-p", JWT_KEYS_DIR])
    ld_library_path = os.getenv("LD_LIBRARY_PATH")
    ld_library_path_with_jansson = str(Path(jansson_library_dir).resolve())+ ((":" + ld_library_path) if ld_library_path else "")
    ld_library_path_with_jansson_env = dict()
    ld_library_path_with_jansson_env.update(os.environ)
    ld_library_path_with_jansson_env["LD_LIBRARY_PATH"] = ld_library_path_with_jansson
    subprocess.check_output([f"{cmake_source_dir}/jwk2key", JWKS_JSON_FILE], cwd=JWT_KEYS_DIR, env=ld_library_path_with_jansson_env)
    subprocess.check_output("echo *.pem > public_keys_jwt.txt", shell=True, cwd=JWT_KEYS_DIR)

    # generate public_keys_jwt_key_id.txt
    with open(JWKS_JSON_FILE, encoding='utf-8') as input_file:
        with open((f"{JWT_KEYS_DIR}/public_keys_jwt_key_id.txt"), 'w', encoding='utf-8') as output_file:
            output_file.write("\n".join(key['kid'] for key in json.load(input_file)['keys']) + "\n")

if __name__ == '__main__':
    main()
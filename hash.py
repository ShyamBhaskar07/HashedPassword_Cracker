import hashlib
import bcrypt
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Hashing functions
def hash_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

def hash_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()

def hash_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_bcrypt(password, hashed_password):
    try:
        return bcrypt.checkpw(password.encode(), hashed_password.encode())
    except ValueError:
        return False

def is_bcrypt_hash(hashed_password):
    # Bcrypt hashes have a fixed length of 60 characters and start with $2b$, $2a$, or $2y$
    return len(hashed_password) == 60 and (hashed_password.startswith('$2b$') or hashed_password.startswith('$2a$') or hashed_password.startswith('$2y$'))

# Function to try all hash functions on a single password
def try_hash_functions(password, hashed_password, hash_functions):
    for hash_function in hash_functions:
        if hash_function.__name__ == 'check_bcrypt':
            if is_bcrypt_hash(hashed_password) and hash_function(password, hashed_password):
                return password
        else:
            if hash_function(password) == hashed_password:
                return password
    return None

# Cracking function using parallel processing
def parallel_crack(hashed_password, password_list, hash_functions, max_workers=4):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_password = {executor.submit(try_hash_functions, password.strip(), hashed_password, hash_functions): password for password in password_list}
        
        for future in tqdm(as_completed(future_to_password), total=len(future_to_password)):
            result = future.result()
            if result:
                return result
    return None

# Main function
def main():
    hashed_password = input("Enter the hashed password: ").strip()
    with open('passwords.txt', 'r') as file:
        password_list = file.readlines()

    # Define hash functions and include bcrypt checking
    hash_functions = [hash_md5, hash_sha1, hash_sha256, check_bcrypt]

    cracked_password = parallel_crack(hashed_password, password_list, hash_functions)

    if cracked_password:
        print(f"Password found: {cracked_password}")
    else:
        print("Password not found in the list.")

if __name__ == "__main__":
    main()

# Password Cracker

## Overview

This project is a simple password cracker that takes a hashed password as input and attempts to find a matching password from a given list of sample passwords.

## Requirements

Make sure you have the following packages installed:

```bash
pip install bcrypt numpy tqdm
```

# How It Works
Input: Provide the hashed password from any hash function.
Password List: Ensure you have a file named passwords.txt in the project directory. This file should contain a list of sample passwords.
Cracking: The tool will attempt to crack the hashed password by comparing it against each password in the passwords.txt file.
Output: If a match is found, it returns the password that matches the hashed input.
# Usage
Prepare Password List: Create a passwords.txt file with one password per line.
Run the Script: Execute the script to start the cracking process

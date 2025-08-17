# license_generator.py
import hashlib
import datetime

def generate_license_hash(expiry_date_str: str, transaction_limit: int, secret_key: str) -> str:
    """
    Generates a SHA256 hash based on the expiry date, transaction limit, and a secret key.

    Args:
        expiry_date_str: The expiry date in 'YYYY-MM-DD' format.
        transaction_limit: The maximum number of transactions allowed.
        secret_key: A secret key used to salt the hash, ensuring its integrity.

    Returns:
        A SHA256 hex digest string representing the license hash.
    """
    # Combine the license components into a single string
    # It's crucial that the order and format here match the validation logic in app.py
    license_string = f"{expiry_date_str}|{transaction_limit}|{secret_key}"

    # Hash the combined string using SHA256
    hash_object = hashlib.sha256(license_string.encode('utf-8'))
    return hash_object.hexdigest()

if __name__ == '__main__':
    # This block allows you to run this script independently to generate hashes.
    # In a real application, the secret_key would be stored securely.
    # For this example, it's hardcoded for demonstration.
    EXAMPLE_SECRET_KEY = "your_super_secret_license_key_replace_this_too" # Matches app.py

    print("--- License Hash Generator ---")
    while True:
        expiry_date_input = input("Enter license expiry date (YYYY-MM-DD): ")
        try:
            # Validate date format
            datetime.datetime.strptime(expiry_date_input, '%Y-%m-%d').date()
            break
        except ValueError:
            print("Invalid date format. Please use YYYY-MM-DD.")

    while True:
        transaction_limit_input = input("Enter transaction limit (e.g., 1000, 9999999 for effectively unlimited): ")
        try:
            transaction_limit = int(transaction_limit_input)
            if transaction_limit < 0:
                print("Transaction limit cannot be negative. Please enter a non-negative number.")
            else:
                break
        except ValueError:
            print("Invalid input. Please enter a whole number for the transaction limit.")

    generated_hash = generate_license_hash(expiry_date_input, transaction_limit, EXAMPLE_SECRET_KEY)
    print(f"\nGenerated License Hash: {generated_hash}")
    print(f"Expiry Date: {expiry_date_input}")
    print(f"Transaction Limit: {transaction_limit}")
    print("\nCopy this hash and the corresponding expiry date/transaction limit into your admin panel.")

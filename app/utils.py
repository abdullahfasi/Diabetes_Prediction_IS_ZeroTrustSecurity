import hashlib

def hash_log_file(log_path):
    with open(log_path, 'rb') as f:
        content = f.read()
    return hashlib.sha256(content).hexdigest()

def save_log_hash(log_path):
    hash_value = hash_log_file(log_path)
    with open(log_path + ".hash", "w") as hf:
        hf.write(hash_value)

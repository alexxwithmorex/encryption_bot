# Certificate Authority — issues and manages user certificates
import os
import glob
import shutil
import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

# generate ECC key pair using standard curve P-256 (SECP256R1)
def generate_ec_key():
    return ec.generate_private_key(ec.SECP256R1())

# save private key to .pem file
def save_private_key(key, path):
    with open(path, "wb") as f:   # "wb" = write bytes (not text)
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,       # text format
            format=serialization.PrivateFormat.PKCS8,  # standard structure
            encryption_algorithm=serialization.NoEncryption()  # no password
        ))

# save certificate to .pem file
def save_cert(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


# create Certificate Authority

def create_ca():
    one_day = datetime.timedelta(1, 0, 0)
    os.makedirs("data/certs", exist_ok=True)
    key = generate_ec_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'botCA'),]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'botCA'),]))    
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))   #valid for 30 days 
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key.public_key())
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True,)
    certificate = builder.sign(private_key=key, algorithm=hashes.SHA256(),)

    save_private_key(key, "data/certs/ca_key.pem")
    save_cert(certificate, "data/certs/ca_cert.pem")
    print("CA created.")

# issue certificate for user
def issue_cert(username):
    one_day = datetime.timedelta(1, 0, 0)
    os.makedirs(f"data/certs/{username}", exist_ok=True)

    with open("data/certs/ca_key.pem", "rb") as f:
        cert_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("data/certs/ca_cert.pem", "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    key = generate_ec_key(); #user's key
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username),]))
    builder = builder.issuer_name(cert.subject)
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))   #valid for 30 days 
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key.public_key())
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True,)
    certificate = builder.sign(private_key=cert_key, algorithm=hashes.SHA256(),)

    save_private_key(key, f"data/certs/{username}/key.pem")
    save_cert(certificate, f"data/certs/{username}/cert.pem")

    print(f"Certificate issued for {username}. (ca.py) ")

# remove user by deleting their certificate folder
def revoke_cert(username):
    path = f"data/certs/{username}"
    if os.path.exists(path):
        shutil.rmtree(path)
        print(f"{username} removed from group. (from ca.py)")
    else:
        print(f"{username} not found.")

# return list of all users with a valid certificate
def get_members():
    members = []
    for cert_path in glob.glob("data/certs/*/cert.pem"):
        username = cert_path.split(os.sep)[2]       # extract username from path
        if username != "ca":  # skip CA's own cert
            members.append(username)
    return members
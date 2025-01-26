import os
import logging
import sqlite3
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import traceback

# Database setup
def setup_database():
    logging.debug("Setting up the database.")
    conn = sqlite3.connect("certificates.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            cert_path TEXT NOT NULL,
            key_path TEXT NOT NULL,
            issued_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            country TEXT NOT NULL,
            state TEXT NOT NULL,
            locality TEXT NOT NULL,
            organization TEXT NOT NULL,
            common_name TEXT NOT NULL,
            revoked INTEGER DEFAULT 0,
            signed_by INTEGER,
            renewed_at TEXT,
            FOREIGN KEY (signed_by) REFERENCES root_certificates(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS root_certificates (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            cert_path TEXT NOT NULL,
            key_path TEXT NOT NULL,
            issued_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            country TEXT NOT NULL,
            state TEXT NOT NULL,
            locality TEXT NOT NULL,
            organization TEXT NOT NULL,
            common_name TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS crl (
            id INTEGER PRIMARY KEY,
            cert_id INTEGER NOT NULL,
            revoked_date TEXT NOT NULL,
            FOREIGN KEY (cert_id) REFERENCES certificates(id)
        )
    """)
    conn.commit()
    conn.close()
    logging.debug("Database setup complete.")

# Root Certificate Generation
def generate_root_certificate(output_folder, key_type="RSA", key_size=2048, validity_days=365, \
                              country="RO", state="Timis", locality="Timisoara", \
                              organization="UVT", common_name="UVT Root CA"):
    logging.info("Generating root certificate.")
    
    if key_type == "RSA":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_type == "ECC":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError("Unsupported key type. Choose 'RSA' or 'ECC'.")

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    # Use common name as the filename
    cert_path = os.path.join(output_folder, f"{common_name}_root_cert.pem")
    key_path = os.path.join(output_folder, f"{common_name}_root_key.pem")

    with open(cert_path, "wb") as f:
        f.write(root_cert.public_bytes(Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))

    logging.info(f"Root certificate saved at {cert_path}")
    logging.info(f"Root private key saved at {key_path}")

    conn = sqlite3.connect("certificates.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO root_certificates (name, cert_path, key_path, issued_date, expiry_date, country, state, locality, organization, common_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            common_name,
            cert_path,
            key_path,
            datetime.utcnow().strftime("%Y-%m-%d"),
            (datetime.utcnow() + timedelta(days=validity_days)).strftime("%Y-%m-%d"),
            country,
            state,
            locality,
            organization,
            common_name
        ),
    )
    conn.commit()
    conn.close()

    return cert_path, key_path

# Certificate Issuance
def issue_certificate(subject_name, root_cert_path, root_key_path, output_folder, root_cert_id, key_type="RSA", key_size=2048, \
                      validity_days=365, country="RO", state="Timis", locality="Timisoara", \
                      organization="UVT"):
    logging.info(f"Issuing certificate for {subject_name}.")

    # Validate the root certificate
    if not validate_certificate(root_cert_path, root_cert_path, root_cert_id):
        logging.error("Root certificate validation failed. Cannot issue a new certificate.")
        raise ValueError("Root certificate validation failed.")

    with open(root_cert_path, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())

    with open(root_key_path, "rb") as f:
        root_key = serialization.load_pem_private_key(f.read(), password=None)

    if key_type == "RSA":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_type == "ECC":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError("Unsupported key type. Choose 'RSA' or 'ECC'.")

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
        .sign(root_key, hashes.SHA256())
    )

    cert_path = os.path.join(output_folder, f"{subject_name}_cert.pem")
    key_path = os.path.join(output_folder, f"{subject_name}_key.pem")

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))

    logging.info(f"Certificate for {subject_name} saved at {cert_path}")
    logging.info(f"Private key for {subject_name} saved at {key_path}")

    return cert_path, key_path

# Certificate Validation
def validate_certificate(cert_path, root_cert_path, cert_id):
    """
    Validates a certificate against the root certificate and checks revocation status
    in both the database and the CRL file.
    
    Parameters:
        cert_path (str): Path to the certificate to validate.
        root_cert_path (str): Path to the root certificate.
    
    Returns:
        bool: True if the certificate is valid, False otherwise.
    """
    try:
        # Load the certificate to validate
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        # Load the root certificate
        with open(root_cert_path, "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())

        # Verify signature
        public_key = root_cert.public_key()
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),  # Required padding
            cert.signature_hash_algorithm,
        )

        # Check validity period
        now = datetime.utcnow()
        if not (cert.not_valid_before <= now <= cert.not_valid_after):
            logging.warning(f"Certificate {cert.subject} is expired or not yet valid.")
            return False

        # Check revocation in the CRL file
        crl_revoked = False
        try:
            with open("crl.pem", "rb") as f:
                crl = x509.load_pem_x509_crl(f.read())
            for revoked_cert in crl:
                if revoked_cert.serial_number == cert.serial_number:
                    crl_revoked = True
                    break
        except FileNotFoundError:
            logging.warning("CRL file 'crl.pem' not found. Skipping CRL check.")
        except Exception as e:
            logging.error(f"Failed to parse CRL: {e}")
            logging.debug(traceback.format_exc())

        if crl_revoked:
            logging.warning(f"Certificate {cert.subject} is revoked in the CRL.")
            return False

        logging.info(f"Certificate {cert.subject} is valid.")
        return True

    except Exception as e:
        logging.error(f"Certificate validation failed: {e}")
        logging.debug(traceback.format_exc())
        return False

def generate_crl(root_cert_path, root_key_path):
    conn = sqlite3.connect("certificates.db")
    cursor = conn.cursor()
    cursor.execute("SELECT cert_id FROM crl")
    revoked_cert_serials = [row[0] for row in cursor.fetchall()]
    conn.close()

    # Load the root certificate and key
    with open(root_cert_path, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())
    with open(root_key_path, "rb") as f:
        root_key = serialization.load_pem_private_key(f.read(), password=None)

    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(root_cert.subject)
    crl_builder = crl_builder.last_update(datetime.utcnow())
    crl_builder = crl_builder.next_update(datetime.utcnow() + timedelta(days=30))

    for serial in revoked_cert_serials:
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(datetime.utcnow()).build()
        crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

    crl = crl_builder.sign(private_key=root_key, algorithm=hashes.SHA256())

    with open("crl.pem", "wb") as f:
        f.write(crl.public_bytes(Encoding.PEM))

    logging.info("CRL generated and saved as 'crl.pem'")
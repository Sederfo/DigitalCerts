from flask import Flask, request, jsonify
import os
import sqlite3 
from cert_utils import issue_certificate, setup_database, generate_crl, generate_root_certificate
from datetime import datetime, timedelta
import pathlib

PATH = pathlib.Path(__file__).parent.absolute()

app = Flask(__name__)

setup_database()

# Generate root certificate
@app.route('/certificates/root', methods=['POST'])
def generate_root_certificate_endpoint():
    data = request.json
    name = data.get("name", None)
    key_type = data.get("key_type", "RSA")
    validity_days = data.get("validity_days", 365)
    country = data.get("country", "RO")
    state = data.get("state", "Timis")
    locality = data.get("locality", "Timisoara")
    organization = data.get("organization", "UVT")
    output_folder = data.get("output_folder", "certs/")

    if not name:
        return jsonify({"error": "Name is required."}), 400

    os.makedirs(output_folder, exist_ok=True)

    output_folder = os.path.join(PATH, output_folder)

    try:
        cert_path, key_path = generate_root_certificate(
            output_folder=output_folder,
            key_type=key_type,
            validity_days=validity_days,
            country=country,
            state=state,
            locality=locality,
            organization=organization,
            common_name=name,
        )
        return jsonify({"message": "Root certificate generated successfully", "cert_path": cert_path, "key_path": key_path}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/certificates/issue', methods=['POST'])
def issue_certificate_endpoint():
    data = request.json
    subject_name = data.get("subject_name", None)

    if not subject_name:
        return jsonify({"error": "Subject name is required."}), 400

    key_type = data.get("key_type", "RSA")
    validity_days = data.get("validity_days", 365)

    country = data.get("country", "RO")
    state = data.get("state", "Timis")
    locality = data.get("locality", "Timisoara")
    organization = data.get("organization", "UVT")


    output_folder = data.get("output_folder", "certs/")
    root_cert_id = data.get("root_cert_id", None)

    if not root_cert_id:
        return jsonify({"error": "Root certificate ID is required."}), 500

    os.makedirs(output_folder, exist_ok=True)

    output_folder = os.path.join(PATH, output_folder)

    try:
        # Get the root certificate paths
        conn = sqlite3.connect("certificates.db")
        cursor = conn.cursor()
        cursor.execute(f"SELECT cert_path, key_path FROM root_certificates WHERE id = ?", (root_cert_id,))
        root_cert_paths = cursor.fetchone()
        if not root_cert_paths:
            return jsonify({"error": "Root certificate paths not found."}), 500

        root_cert_path, root_key_path = root_cert_paths

        cert_path, key_path = issue_certificate(
            subject_name=subject_name,
            root_cert_path=root_cert_path,
            root_key_path=root_key_path,
            output_folder=output_folder,
            root_cert_id=1,  # Assuming root cert ID is 1
            key_type=key_type,
            validity_days=validity_days,
            country=country,
            state=state,
            locality=locality,
            organization=organization,
        )

        conn = sqlite3.connect("certificates.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO certificates (name, cert_path, key_path, issued_date, expiry_date, country, state, locality, organization, common_name, revoked, signed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                subject_name,
                cert_path,
                key_path,
                datetime.utcnow().strftime("%Y-%m-%d"),
                (datetime.utcnow() + timedelta(days=validity_days)).strftime("%Y-%m-%d"),
                country,
                state,
                locality,
                organization,
                subject_name,  # Assuming common_name is the same as subject_name
                0,  # Default value for revoked
                root_cert_id  # ID of the root certificate used to sign this certificate
            ),
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "Certificate issued successfully", "cert_path": cert_path, "key_path": key_path}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/certificates/revoke', methods=['POST'])
def revoke_certificate_endpoint():
    data = request.json
    cert_name = data.get("cert_name")

    try:
        conn = sqlite3.connect("certificates.db")
        cursor = conn.cursor()
        
        # Get the root certificate paths
        cursor.execute("SELECT signed_by FROM certificates WHERE name = ?", (cert_name,))
        signed_by = cursor.fetchone()
        if not signed_by:
            return jsonify({"error": "Root certificate not found for the given certificate."}), 400

        cursor.execute("SELECT cert_path, key_path FROM root_certificates WHERE id = ?", (signed_by[0],))
        root_cert_paths = cursor.fetchone()
        if not root_cert_paths:
            return jsonify({"error": "Root certificate paths not found."}), 400

        root_cert_path, root_key_path = root_cert_paths

        # Update the certificate as revoked
        cursor.execute("UPDATE certificates SET revoked = 1 WHERE name = ?", (cert_name,))
        cursor.execute("INSERT INTO crl (cert_id, revoked_date) VALUES ((SELECT id FROM certificates WHERE name = ?), ?)", (cert_name, datetime.utcnow().strftime("%Y-%m-%d")))
        conn.commit()
        conn.close()

        # Generate the CRL
        generate_crl(root_cert_path, root_key_path)

        return jsonify({"message": f"Certificate '{cert_name}' has been revoked and CRL updated"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/certificates', methods=['GET'])
def list_certificates_endpoint():
    try:
        conn = sqlite3.connect("certificates.db")
        cursor = conn.cursor()
        cursor.execute("SELECT name, issued_date, expiry_date, revoked FROM certificates")
        certs = cursor.fetchall()
        conn.close()

        certs_data = [
            {
                "name": cert[0],
                "issued_date": cert[1],
                "expiry_date": cert[2],
                "revoked": bool(cert[3]),
            }
            for cert in certs
        ]

        return jsonify(certs_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/rootcertificates', methods=['GET'])
def list_root_certificates_endpoint():
    try:
        conn = sqlite3.connect("certificates.db")
        cursor = conn.cursor()
        cursor.execute("SELECT name, issued_date, expiry_date, country, state, locality, organization, common_name FROM root_certificates")
        root_certs = cursor.fetchall()
        conn.close()

        root_certs_data = [
            {
                "name": root_cert[0],
                "issued_date": root_cert[1],
                "expiry_date": root_cert[2],
                "country": root_cert[3],
                "state": root_cert[4],
                "locality": root_cert[5],
                "organization": root_cert[6],
                "common_name": root_cert[7],
            }
            for root_cert in root_certs
        ]

        return jsonify(root_certs_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5005)

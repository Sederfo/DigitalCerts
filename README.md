# DigitalCerts

Project for Cryptography course UVT AIDC Semester 1 2025.

## Dependencies

This project requires the following Python packages to run:

- ```Flask```: A lightweight WSGI web application framework for building the API.  
- ```cryptography```: A library providing cryptographic recipes and primitives for secure certificate management.  
- ```pycryptodome```: A self-contained cryptographic library for handling encryption and related operations.  

### Installation

You can install all the dependencies using pip:

```
pip install Flask cryptography pycryptodome
```


## Project requirements:
Develop a digital certificate system capable of securing communications over an unsecured channel with a similar structure as the X.509 standard. The certificate must support generating a root certificate, issuing new certificates, revoking certificates, setting expiration dates, and renewing certificates. The certificates should facilitate key exchange for symmetric encryption, as implemented in Project 1.

### Root Certificate Generation:
Generate a self-signed root certificate using RSA/ECC keys.
The root certificate should have a configurable expiration date.

**Implementation:**
- **GUI (certificate_manager.py):** The `generate_root_certificate` function is called from the GUI to create a new root certificate. The user inputs the necessary details through a form, and the certificate is saved to the specified location.
- **API (app.py):** An endpoint is provided to generate a root certificate by sending a POST request with the required parameters.

### Certificate Issuance:
Generate certificates derived from the root certificate.
Ensure certificates contain the public key, certificate serial number, and expiration date.
The root certificate must digitally sign issued certificates.

**Implementation:**
- **GUI (certificate_manager.py):** The `issue_certificate` function is used to issue new certificates. The user selects the root certificate and provides the details for the new certificate through the GUI.
- **API (app.py):** An endpoint is available to issue new certificates by sending a POST request with the necessary details.

### Certificate Revocation:
Implement a Certificate Revocation List (CRL).
Ensure the CRL can revoke certificates and is verified during validation.

**Implementation:**
- **GUI (certificate_manager.py):** The `revoke_cert` function allows users to revoke certificates. The revoked certificates are added to the CRL, which is updated and saved.
- **API (app.py):** An endpoint is provided to revoke certificates by sending a POST request with the certificate details.

### Expiration and Renewal:
Enforce expiration dates for all certificates.
Implement a renewal mechanism that issues a new certificate before expiration.

**Implementation:**
- **GUI (certificate_manager.py):** The `renew_cert` function enables users to renew certificates. The user selects the certificate to renew, and a new certificate is issued with an updated expiration date.
- **API (app.py):** An endpoint is available to renew certificates by sending a POST request with the certificate details.

### Key Exchange Integration:
Use the certificates to establish a secure key exchange.
The exchanged key must be used for symmetric encryption as developed in Project 1.

**Implementation:**
- **GUI (certificate_manager.py):** The key exchange process is integrated into the certificate issuance and renewal processes. The exchanged keys are used for symmetric encryption.
- **API (app.py):** Endpoints are provided to facilitate key exchange and encryption using the issued certificates.

## Tech Stack Used:
- **Flask:** Used to create the RESTful API endpoints for certificate management.
- **SQLite:** Used as the database to store certificate information.
- **PyCryptodome:** Used for cryptographic operations such as key generation, encryption, and decryption.
- **Cryptography:** Used for handling X.509 certificates and related cryptographic functions.
- **Tkinter:** Used to create the GUI for managing certificates.
- **Logging:** Used for logging application events and errors.

## Deliverables:
Codebase: A complete, functional program implementing the digital certificate system.
A code documentation report that includes:
- Explanation of the cryptographic concepts used.
- Description of the certificate structure and validation process.
- Test results demonstrating certificate creation, revocation, and key exchange.

## Evaluation Criteria:
- Correctness and security of the implementation. 30p
- Compliance with the assignment requirements. 30p
- Code readability and documentation quality. 20p
- Successful demonstration of key exchange and encryption functionality. 20p

## Bonus: Implement a basic Certificate Authority (CA) server for automating certificate management. 20p

# Certificate Management API

This API provides endpoints for managing root certificates, issuing new certificates, revoking certificates, and listing certificates.

---

## Endpoints

### 1. Generate Root Certificate
- **Endpoint:** ```/certificates/root```  
- **Method:** ```POST```  
- **Description:** Generates a self-signed root certificate.  
- **Request Body:**  
  ```
  { 
    "name": "Root CA", 
    "key_type": "RSA", 
    "validity_days": 365, 
    "country": "RO", 
    "state": "Timis", 
    "locality": "Timisoara", 
    "organization": "UVT", 
    "common_name": "UVT Root CA", 
    "output_folder": "certs/" 
  }
  ```

---

### 2. Issue Certificate
- **Endpoint:** ```/certificates/issue```  
- **Method:** ```POST```  
- **Description:** Issues a new certificate signed by the root certificate.  
- **Request Body:**  
  ```
  { 
    "subject_name": "John Doe", 
    "key_type": "RSA", 
    "validity_days": 365, 
    "country": "RO", 
    "state": "Timis", 
    "locality": "Timisoara", 
    "organization": "UVT", 
    "output_folder": "certs/", 
    "root_cert_id": 1 
  }
  ```

---

### 3. Revoke Certificate
- **Endpoint:** ```/certificates/revoke```  
- **Method:** ```POST```  
- **Description:** Revokes a certificate and updates the CRL.  
- **Request Body:**  
  ```
  { 
    "cert_name": "John Doe" 
  }
  ```

---

### 4. List Certificates
- **Endpoint:** ```/certificates```  
- **Method:** ```GET```  
- **Description:** Lists all issued certificates.  
- **Response:**  
  ```
  [ 
    { 
      "name": "John Doe", 
      "issued_date": "2023-01-01", 
      "expiry_date": "2024-01-01", 
      "revoked": false 
    }, 
    { 
      "name": "Jane Smith", 
      "issued_date": "2023-02-01", 
      "expiry_date": "2024-02-01", 
      "revoked": true 
    } 
  ]
  ```

---

### 5. List Root Certificates
- **Endpoint:** ```/rootcertificates```  
- **Method:** ```GET```  
- **Description:** Lists all root certificates.  
- **Response:**  
  ```
  [ 
    { 
      "name": "Root CA", 
      "issued_date": "2023-01-01", 
      "expiry_date": "2028-01-01", 
      "country": "RO", 
      "state": "Timis", 
      "locality": "Timisoara", 
      "organization": "UVT", 
      "common_name": "UVT Root CA" 
    } 
  ]
  ```

## Usage

### Running the Flask API Server
To start the Flask API server, run the ```app.py``` script. This will start the server on port 5005.  
```python app.py```

---

### Running the Certificate Manager GUI
To open the Tkinter-based GUI for managing certificates, run the ```certificate_manager.py``` script.  
```python certificate_manager.py```

---

### Running Key Exchange Example
To run the key exchange example, execute the ```key_exchange.py``` script. This script demonstrates the process of exchanging keys and encrypting/decrypting a message.  
```python key_exchange.py```

---

### Running DESX3 Example
To run the DESX3 encryption/decryption example, execute the ```desx3.py``` script. This script demonstrates the process of encrypting and decrypting a message using custom DESX3 functions. This is part of project 1.  
```python desx3.py```


## Contributors

- Marius Vlad-Andrei
- Nadia Feil  
- Ramos Ivanilson

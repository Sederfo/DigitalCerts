import os
import json
import logging
import sqlite3
from tkinter import Tk, Label, Button, Entry, Listbox, END, filedialog, messagebox, Toplevel, OptionMenu, StringVar, Frame
from tkinter import ttk
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
import traceback
from cert_utils import generate_root_certificate, issue_certificate, generate_crl, setup_database

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


# GUI Application
def main():
    logging.debug("Starting the Digital Certificate Manager application.")
    setup_database()

    def revoke_cert():
        logging.debug("Certificate revocation process started.")
        selected = cert_tree.selection()
        if not selected:
            logging.warning("No certificate selected for revocation.")
            messagebox.showwarning("Warning", "Please select a certificate to revoke.")
            return

        selected_cert_id = cert_tree.item(selected[0])['values'][0]
        conn = sqlite3.connect("certificates.db")
        cursor = conn.cursor()

        # Get the signed_by field from the certificates table
        cursor.execute("SELECT signed_by FROM certificates WHERE id = ?", (selected_cert_id,))
        signed_by = cursor.fetchone()[0]
        if not signed_by:
            logging.warning("No root certificate found for the selected certificate.")
            messagebox.showwarning("Warning", "No root certificate found for the selected certificate.")
            conn.close()
            return

        # Get the root_cert_path and root_key_path from the root_certificates table
        cursor.execute("SELECT cert_path, key_path FROM root_certificates WHERE id = ?", (signed_by,))
        root_cert_path, root_key_path = cursor.fetchone()

        # Update the certificate as revoked
        cursor.execute("UPDATE certificates SET revoked = 1 WHERE id = ?", (selected_cert_id,))
        cursor.execute("INSERT INTO crl (cert_id, revoked_date) VALUES (?, ?)", (selected_cert_id, datetime.utcnow().strftime("%Y-%m-%d")))
        conn.commit()
        conn.close()

        # Generate the CRL
        generate_crl(root_cert_path, root_key_path)

        update_cert_list()
        messagebox.showinfo("Success", f"Certificate '{selected_cert_id}' has been revoked.")
        logging.debug(f"Certificate '{selected_cert_id}' successfully revoked.")


    def update_cert_list():
        logging.debug("Updating certificate list.")
        for item in cert_tree.get_children():
            cert_tree.delete(item)
        conn = sqlite3.connect("certificates.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM certificates")
        for row in cursor.fetchall():
            cert_tree.insert("", END, values=row)
        conn.close()

    def open_select_root_certificate_window(callback):
        logging.debug("Opening select root certificate window.")
        select_window = Toplevel(root)
        select_window.title("Select Root Certificate")

        columns = ("id", "name", "cert_path", "key_path", "issued_date", "expiry_date", "country", "state", "locality", "organization", "common_name")
        tree = ttk.Treeview(select_window, columns=columns, show="headings")
        
        for col in columns:
            tree.heading(col, text=col.replace("_", " ").title(), anchor="center")
            tree.column(col, anchor="center", width=100)

        tree.grid(row=0, column=0, columnspan=2)

        conn = sqlite3.connect("certificates.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM root_certificates")
        for row in cursor.fetchall():
            tree.insert("", END, values=row)
        conn.close()

        def on_select():
            selected = tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Please select a root certificate.")
                return
            root_cert = tree.item(selected[0])['values']
            select_window.destroy()
            callback(root_cert)

        Button(select_window, text="Select", command=on_select).grid(row=1, column=0)
        Button(select_window, text="Cancel", command=select_window.destroy).grid(row=1, column=1)

    def open_issue_certificate_window():
        logging.debug("Opening issue certificate window.")
        issue_window = Toplevel(root)
        issue_window.title("Issue Certificate")

        Label(issue_window, text="Name:").grid(row=0, column=0)
        name_entry = Entry(issue_window)
        name_entry.grid(row=0, column=1)

        Label(issue_window, text="Key Type:").grid(row=1, column=0)
        key_type_entry = StringVar(issue_window)
        key_type_entry.set("RSA")  # default value
        key_type_menu = OptionMenu(issue_window, key_type_entry, "RSA", "ECC")
        key_type_menu.grid(row=1, column=1)

        Label(issue_window, text="Validity Days:").grid(row=2, column=0)
        expiration_entry = Entry(issue_window)
        expiration_entry.grid(row=2, column=1)
        expiration_entry.insert(0, "365")

        Label(issue_window, text="Country:").grid(row=3, column=0)
        country_entry = Entry(issue_window)
        country_entry.grid(row=3, column=1)
        country_entry.insert(0, "RO")

        Label(issue_window, text="State:").grid(row=4, column=0)
        state_entry = Entry(issue_window)
        state_entry.grid(row=4, column=1)
        state_entry.insert(0, "Timis")

        Label(issue_window, text="Locality:").grid(row=5, column=0)
        locality_entry = Entry(issue_window)
        locality_entry.grid(row=5, column=1)
        locality_entry.insert(0, "Timisoara")

        Label(issue_window, text="Organization:").grid(row=6, column=0)
        org_entry = Entry(issue_window)
        org_entry.grid(row=6, column=1)
        org_entry.insert(0, "UVT")


        def issue_cert_from_window(window, root_cert):
            logging.debug("Issuing certificate from window inputs.")
            
            root_cert_id = root_cert[0]
            root_cert_path = root_cert[2]
            root_key_path = root_cert[3]

            subject_name = name_entry.get()
            if not subject_name:
                messagebox.showwarning("Warning", "Name is a required field.")
                return

            key_type = key_type_entry.get()
            validity_days = int(expiration_entry.get())
            country = country_entry.get()
            state = state_entry.get()
            locality = locality_entry.get()
            organization = org_entry.get()
            
            output_folder = filedialog.askdirectory()
            if not output_folder:
                logging.warning("No output folder selected.")
                messagebox.showwarning("Warning", "Please select an output folder.")
                return

            try:
                cert_path, key_path = issue_certificate(
                    subject_name,
                    root_cert_path,
                    root_key_path,
                    output_folder,
                    root_cert_id,
                    key_type=key_type,
                    validity_days=validity_days,
                    country=country,
                    state=state,
                    locality=locality,
                    organization=organization
                )
                conn = sqlite3.connect("certificates.db")
                cursor = conn.cursor()
                logging.debug(f"{subject_name=} {cert_path=} {key_path=} {validity_days=} {country=} {state=} {locality=} {organization=} {root_cert_id=}")
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
                messagebox.showinfo("Info", f"Certificate issued successfully.\nCertificate Path: {cert_path}\nKey Path: {key_path}")
            except Exception as e:
                traceback.print_exc()
                logging.error(f"Error issuing certificate: {e}")
                messagebox.showerror("Error", f"Failed to issue certificate: {e}")
            
            window.destroy()
            update_cert_list()

        def on_select_root_cert(root_cert):
            logging.debug(f"{root_cert=}")
            issue_cert_from_window(issue_window, root_cert)

        Button(issue_window, text="Select Root Certificate", command=lambda: open_select_root_certificate_window(on_select_root_cert)).grid(row=7, column=0)
        Button(issue_window, text="Cancel", command=issue_window.destroy).grid(row=7, column=1)

    def open_generate_root_certificate_window():
        issue_window = Toplevel(root)
        issue_window.title("Generate Root Certificate")

        Label(issue_window, text="Name:").grid(row=0, column=0)
        name_entry = Entry(issue_window)
        name_entry.grid(row=0, column=1)

        Label(issue_window, text="Key Type:").grid(row=1, column=0)
        key_type_var = StringVar(issue_window)
        key_type_var.set("RSA")  # default value
        key_type_menu = OptionMenu(issue_window, key_type_var, "RSA", "ECC")
        key_type_menu.grid(row=1, column=1)

        Label(issue_window, text="Validity Days:").grid(row=2, column=0)
        expiration_entry = Entry(issue_window)
        expiration_entry.grid(row=2, column=1)
        expiration_entry.insert(0, "365")

        Label(issue_window, text="Country:").grid(row=3, column=0)
        country_entry = Entry(issue_window)
        country_entry.grid(row=3, column=1)
        country_entry.insert(0, "RO")

        Label(issue_window, text="State:").grid(row=4, column=0)
        state_entry = Entry(issue_window)
        state_entry.grid(row=4, column=1)
        state_entry.insert(0, "Timis")

        Label(issue_window, text="Locality:").grid(row=5, column=0)
        locality_entry = Entry(issue_window)
        locality_entry.grid(row=5, column=1)
        locality_entry.insert(0, "Timisoara")

        Label(issue_window, text="Organization:").grid(row=6, column=0)
        org_entry = Entry(issue_window)
        org_entry.grid(row=6, column=1)
        org_entry.insert(0, "UVT")

        def generate_root_cert_from_window(window, key_type_var):
            logging.debug("Generating root certificate from window inputs.")
            
            name = name_entry.get()
            if not name:
                messagebox.showwarning("Warning", "Name is a required field.")
                return
            
            key_type = key_type_var.get()
            validity_days = int(expiration_entry.get())
            country = country_entry.get()
            state = state_entry.get()
            locality = locality_entry.get()
            organization = org_entry.get()
            
            conn = sqlite3.connect("certificates.db")
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM root_certificates WHERE name = ?", (name,))
            if cursor.fetchone()[0] > 0:
                logging.warning(f"Root certificate with name '{name}' already exists.")
                messagebox.showwarning("Warning", f"Root certificate with name '{name}' already exists.")
                conn.close()
                return

            output_folder = filedialog.askdirectory()
            if not output_folder:
                logging.warning("No output folder selected.")
                messagebox.showwarning("Warning", "Please select an output folder.")
                conn.close()
                return

            try:
                cert_path, key_path = generate_root_certificate(
                    output_folder,
                    key_type=key_type,
                    validity_days=validity_days,
                    country=country,
                    state=state,
                    locality=locality,
                    organization=organization,
                    common_name=name
                )
                messagebox.showinfo("Info", f"Root certificate generated successfully.\nCertificate Path: {cert_path}\nKey Path: {key_path}")
            except Exception as e:
                logging.error(f"Error generating root certificate: {e}")
                messagebox.showerror("Error", f"Failed to generate root certificate: {e}")
            
            conn.close()
            window.destroy()
            update_cert_list()

        Button(issue_window, text="Generate", command=lambda: generate_root_cert_from_window(issue_window, key_type_var)).grid(row=7, column=0)
        Button(issue_window, text="Cancel", command=issue_window.destroy).grid(row=7, column=1)

    
    def open_view_crl_window():
        logging.debug("Opening view CRL window.")
        view_window = Toplevel(root)
        view_window.title("View CRL")
    
        columns = ("cert_id", "revoked_date", "name", "issued_date", "expiry_date", "country", "state", "locality", "organization", "common_name")
        tree = ttk.Treeview(view_window, columns=columns, show="headings")
        
        for col in columns:
            tree.heading(col, text=col.replace("_", " ").title(), anchor="center")
            tree.column(col, anchor="center", width=100)
    
        tree.grid(row=0, column=0, columnspan=2)
    
        conn = sqlite3.connect("certificates.db")
        cursor = conn.cursor()
        cursor.execute("""
            SELECT crl.cert_id, crl.revoked_date, certificates.name, certificates.issued_date, certificates.expiry_date, 
                   certificates.country, certificates.state, certificates.locality, certificates.organization, certificates.common_name
            FROM crl
            JOIN certificates ON crl.cert_id = certificates.id
        """)
        for row in cursor.fetchall():
            tree.insert("", END, values=row)
        conn.close()
    
        Button(view_window, text="Close", command=view_window.destroy).grid(row=1, column=0, columnspan=2)
    
    def renew_cert():
        logging.debug("Certificate renewal process started.")
        selected = cert_tree.selection()
        if not selected:
            logging.warning("No certificate selected for renewal.")
            messagebox.showwarning("Warning", "Please select a certificate to renew.")
            return

        selected_cert_id = cert_tree.item(selected[0])['values'][0]
        conn = sqlite3.connect("certificates.db")
        cursor = conn.cursor()

        # Use cert_tree.item to get the details of the selected certificate
        logging.debug(f"{cert_tree.item(selected[0])=}")
        cert_details = cert_tree.item(selected[0])['values']
        (cert_id, name, cert_path, key_path, issued_date, expiry_date, country, state, locality, organization, common_name, revoked, signed_by, renewed_at) = cert_details

        logging.debug(f"{cert_id=} {name=} {cert_path=} {key_path=} {issued_date=} {expiry_date=} {country=} {state=} {locality=} {organization=} {common_name=} {revoked=} {signed_by=}")

        # Get the root_cert_path and root_key_path from the root_certificates table
        cursor.execute("SELECT cert_path, key_path FROM root_certificates WHERE id = ?", (cert_id,))
        root_cert_path, root_key_path = cursor.fetchone()

        # Generate a new certificate with the same details
        new_cert_path, new_key_path = issue_certificate(
            subject_name=name,
            root_cert_path=root_cert_path,
            root_key_path=root_key_path,
            output_folder=os.path.dirname(cert_path),
            root_cert_id=signed_by,
            key_type="RSA",  # Assuming RSA, you can modify as needed
            validity_days=365,  # Assuming 1 year validity, you can modify as needed
            country=country,
            state=state,
            locality=locality,
            organization=organization
        )

        # Update the certificate details in the database
        cursor.execute("UPDATE certificates SET cert_path = ?, key_path = ?, issued_date = ?, expiry_date = ?, renewed_at = ? WHERE id = ?",
                    (new_cert_path, new_key_path, datetime.utcnow().strftime("%Y-%m-%d"), (datetime.utcnow() + timedelta(days=365)).strftime("%Y-%m-%d"), datetime.utcnow().strftime("%Y-%m-%d"), selected_cert_id))
        conn.commit()
        conn.close()

        update_cert_list()
        messagebox.showinfo("Success", f"Certificate '{selected_cert_id}' has been renewed.")
        logging.debug(f"Certificate '{selected_cert_id}' successfully renewed.")

    def open_view_root_certificates_window():
        logging.debug("Opening view root certificates window.")
        view_window = Toplevel(root)
        view_window.title("View Root Certificates")

        columns = ("name", "issued_date", "expiry_date", "country", "state", "locality", "organization", "common_name")
        tree = ttk.Treeview(view_window, columns=columns, show="headings")
        
        for col in columns:
            tree.heading(col, text=col.replace("_", " ").title(), anchor="center")
            tree.column(col, anchor="center", width=100)

        tree.grid(row=0, column=0, columnspan=2)

        conn = sqlite3.connect("certificates.db")
        cursor = conn.cursor()
        cursor.execute("SELECT name, issued_date, expiry_date, country, state, locality, organization, common_name FROM root_certificates")
        for row in cursor.fetchall():
            tree.insert("", END, values=row)
        conn.close()

        Button(view_window, text="Close", command=view_window.destroy).grid(row=1, column=0, columnspan=2)

    root = Tk()
    root.title("Digital Certificate Manager")

    Label(root, text="Existing Certificates:").grid(row=0, column=0)
    
    columns = [
        "id",
        "name",
        "cert_path",
        "key_path",
        "issued_date",
        "expiry_date",
        "country",
        "state",
        "locality",
        "organization",
        "common_name",
        "revoked",
        "signed_by",
        "renewed_at"
    ]
    cert_tree = ttk.Treeview(root, columns=columns, show="headings")
    
    for col in columns:
        cert_tree.heading(col, text=col.replace("_", " ").title(), anchor="center")
        cert_tree.column(col, anchor="center", width=100)

    cert_tree.grid(row=0, column=0, columnspan=2)

    conn = sqlite3.connect("certificates.db")
    cursor = conn.cursor()
    cursor.execute("SELECT name, issued_date, expiry_date, country, state, locality, organization, common_name, renewed_at FROM certificates")
    for row in cursor.fetchall():
        cert_tree.insert("", END, values=row)
    conn.close()


    button_frame = Frame(root)
    button_frame.grid(row=2, column=0, columnspan=4, pady=10)

    Button(button_frame, text="Issue Certificate", command=open_issue_certificate_window).grid(row=0, column=0, padx=5, pady=5)
    Button(button_frame, text="Revoke Certificate", command=revoke_cert).grid(row=0, column=1, padx=5, pady=5)
    Button(button_frame, text="Generate Root Certificate", command=open_generate_root_certificate_window).grid(row=0, column=2, padx=5, pady=5)
    Button(button_frame, text="View Root Certificates", command=open_view_root_certificates_window).grid(row=0, column=3, padx=5, pady=5)
    Button(button_frame, text="View CRL", command=open_view_crl_window).grid(row=0, column=4, padx=5, pady=5)
    Button(button_frame, text="Renew Certificate", command=renew_cert).grid(row=0, column=5, padx=5, pady=5)
    Button(button_frame, text="Refresh", command=update_cert_list).grid(row=0, column=6, padx=5, pady=5)

    update_cert_list()
    root.mainloop()

if __name__ == "__main__":
    main()
import imaplib
import email
import re
from urllib.parse import urlparse
import time

# Email credentials and server details
EMAIL = 'example@yahoo.com'
PASSWORD = 'pass'  # Use the app-specific password here
IMAP_SERVER = 'imap.mail.yahoo.com'
IMAP_PORT = 993
OUTPUT_FILE = 'suspicious_emails.txt'

# Define the exceptions list with patterns
EXCEPTIONS = [
    'goo.gl/maps',
    'googleapis.com',
    'fonts.gstatic.com',
    'maps.google.com'
    # Add more trusted links or domains here
]

def connect_to_inbox(email, password, server, port):
    mail = imaplib.IMAP4_SSL(server, port)
    mail.login(email, password)
    mail.select('inbox')
    return mail

def search_emails(mail):
    result, data = mail.search(None, 'ALL')
    email_ids = data[0].split()
    return email_ids

def fetch_email(mail, email_id):
    result, data = mail.fetch(email_id, '(RFC822)')
    raw_email = data[0][1]
    return email.message_from_bytes(raw_email)

def extract_links(email_message):
    links = []

    def decode_part(part):
        try:
            return part.get_payload(decode=True).decode()
        except UnicodeDecodeError:
            try:
                return part.get_payload(decode=True).decode('latin-1')
            except UnicodeDecodeError:
                return part.get_payload(decode=True).decode('ISO-8859-1')

    if email_message.is_multipart():
        for part in email_message.walk():
            if part.get_content_type() == 'text/html':
                html_content = decode_part(part)
                links.extend(re.findall(r'href=[\'"]?([^\'" >]+)', html_content))
            elif part.get_content_type() == 'text/plain':
                text_content = decode_part(part)
                links.extend(re.findall(r'(https?://\S+)', text_content))
    else:
        if email_message.get_content_type() == 'text/html':
            html_content = decode_part(email_message)
            links.extend(re.findall(r'href=[\'"]?([^\'" >]+)', html_content))
        elif email_message.get_content_type() == 'text/plain':
            text_content = decode_part(email_message)
            links.extend(re.findall(r'(https?://\S+)', text_content))

    # print(f'Debug: Extracted links - {links}')
    return links

def is_link_in_exceptions(link):
    for exception in EXCEPTIONS:
        if exception in link:
            return True
    return False

def compare_domains(sender, links):
    sender_domain = sender.split('@')[-1]
    suspicious_links = []
    for link in links:
        if is_link_in_exceptions(link):
            continue
        try:
            parsed_url = urlparse(link)
            link_domain = parsed_url.netloc
            
            # Normalize domains for comparison
            sender_domain_normalized = '.'.join(sender_domain.split('.')[-2:])
            link_domain_normalized = '.'.join(link_domain.split('.')[-2:])
            
            if sender_domain_normalized != link_domain_normalized:
                suspicious_links.append(link)
        except ValueError as e:
            print(f"Skipping invalid URL {link}: {e}")
    return suspicious_links

def main():
    mail = connect_to_inbox(EMAIL, PASSWORD, IMAP_SERVER, IMAP_PORT)
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as file:
        # Main logic to process all emails
        email_ids = search_emails(mail)
        for email_id in email_ids:
            try:
                email_message = fetch_email(mail, email_id)
                sender = email.utils.parseaddr(email_message['From'])[1] if email_message['From'] else ''
                subject = str(email_message['Subject']) if email_message['Subject'] else ''
                
                # print(f'Checking email ID {email_id.decode()}: {subject}')
                links = extract_links(email_message)
                suspicious_links = compare_domains(sender, links)
                
                if suspicious_links:
                    file.write(f'Email ID: {email_id.decode()}\n')
                    file.write(f'Subject: {subject}\n')
                    file.write(f'Sender: {sender}\n')
                    file.write(f'Suspicious Links: {suspicious_links}\n')
                    file.write('---\n')
            
            except (TypeError, imaplib.IMAP4.abort) as e:
                print(f"Failed to process email with ID {email_id}: {e}")
                print("Reconnecting to the email server...")
                time.sleep(5)  # Wait before reconnecting
                mail = connect_to_inbox(EMAIL, PASSWORD, IMAP_SERVER, IMAP_PORT)
                continue

if __name__ == "__main__":
    main()

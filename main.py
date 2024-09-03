import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import argparse
from datetime import datetime
import netifaces
import ipaddress
import time
import base64
import gvm
from gvm.protocols.latest import Gmp
from gvm.connections import UnixSocketConnection
from lxml import etree

class Mail:
    def send_email(self, sender, recipients, password, subject, body, smtp_server='smtp.office365.com', smtp_port=587):
        try:
            smtp_server = smtplib.SMTP(smtp_server, smtp_port)
            smtp_server.starttls()
            smtp_server.login(sender, password)
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = subject
            msg.attach(MIMEText(body))
            smtp_server.sendmail(sender, recipients, msg.as_string())
            smtp_server.quit()
            print("Email sent successfully")
        except Exception as e:
            print(f"Error sending email: {e}")

class Scan:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.connection = UnixSocketConnection(path='/run/gvmd/gvmd.sock')
        self.gmp = None
        self.authenticate()

    def authenticate(self):
        try:
            self.gmp = Gmp(connection=self.connection)
            self.gmp.authenticate(username=self.username, password=self.password)
            print("Authenticated successfully")
        except Exception as e:
            print(f"Error establishing connection: {e}")
            self.gmp = None

    def print_version(self):
        try:
            version_response = self.gmp.get_version()
            root = etree.fromstring(version_response)
            version = root.find('.//version').text
            print(f"GVM version: {version}")
        except Exception as e:
            print(f"Error getting version: {e}")

    def create_task(self, name, target_id):
        try:
            response = self.gmp.create_task(
                name=name,
                config_id='2d3f051c-55ba-11e3-bf43-406186ea4fc5',
                target_id=target_id,
                scanner_id='08b69003-5fc2-4037-a479-93b440211c73'
            )
            root = etree.fromstring(response)
            task_id = root.attrib.get("id")
            print(f"Created task ID: {task_id}")
            return task_id
        except Exception as e:
            print(f"Error creating task: {e}")
            return None

    def create_target(self, name, hosts_list):
        try:
            response = self.gmp.create_target(
                name=name,
                hosts=hosts_list,
                port_list_id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
            )
            root = etree.fromstring(response)
            target_id = root.attrib.get("id")
            print(f"Created target ID: {target_id}")
            return target_id
        except Exception as e:
            print(f"Error creating target: {e}")
            return None

    def get_target_id_by_name(self, target_name):
        try:
            response = self.gmp.get_targets(filter_string=f"name={target_name}")
            root = etree.fromstring(response)
            target_element = root.find('.//target')
            if target_element is not None:
                target_id = target_element.attrib.get('id')
                print(f"Found target ID: {target_id}")
                return target_id
            else:
                print("Target not found.")
                return None
        except Exception as e:
            print(f"Error retrieving target ID: {e}")
            return None

    def start_task(self, task_id):
        try:
            task_response = self.gmp.start_task(task_id)
            root = etree.fromstring(task_response)
            status_text = root.attrib.get('status_text')
            print(f"Task Response: {status_text}")
            return task_response
        except Exception as e:
            print(f"Error starting task: {e}")
            return None

    def find_report_id_from_task_response(self, task_response):
        try:
            root = etree.fromstring(task_response)
            report_id = root.find('.//report_id').text
            return report_id
        except Exception as e:
            print(f"Error finding report ID: {e}")
            return None

    def is_task_finished(self, report_id):
        try:
            report = self.gmp.get_report(report_id)
            first_index = report.index('<scan_run_status>')
            last_index = report.index('</scan_run_status>')
            status = report[first_index + len('<scan_run_status>'): last_index]
            print(f"Status of task: {status}")
            return status == "Done"
        except Exception as e:
            print(f"Error checking task status: {e}")
            return False

    def save_report_to_pdf(self, report_id, report_file_name):
        try:
            report = self.gmp.get_report(report_id, report_format_id='c402cc3e-b531-11e1-9163-406186ea4fc5')  # pdf format
            start_index = report.index('</report_format>')
            last_index = report.index('</report>')
            encoded_report_pdf = report[start_index + len('</report_format>'): last_index]
            decoded_bytes = base64.b64decode(encoded_report_pdf)
            with open(report_file_name, 'wb') as f:
                f.write(decoded_bytes)
            print(f"Report saved to {report_file_name}")
        except Exception as e:
            print(f"Error saving report to PDF: {e}")

    def send_report_via_email(self, report_file_name, subject, body, sender, recipients, password, smtp_server='smtp.office365.com', smtp_port=587):
        mail = Mail()
        mail.send_email(sender, recipients, password, subject, body, smtp_server, smtp_port)
        print(f"Report sent via email to {', '.join(recipients)}")

def get_local_subnet_cidr():
    for interface in netifaces.interfaces():
        inet = netifaces.ifaddresses(interface).get(netifaces.AF_INET)
        if inet and not inet[0]['addr'].startswith('127.'):
            addr = inet[0]['addr']
            netmask = inet[0]['netmask']
            cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
            network = ipaddress.IPv4Network(f"{addr}/{netmask}", strict=False)
            return str(network)
    return None

def generate_ip_list(subnet):
    return [str(ip) for ip in ipaddress.IPv4Network(subnet)]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OpenVAS Scan and Email Report")
    parser.add_argument('--sender-email', required=True, help="Sender's email address")
    parser.add_argument('--sender-password', required=True, help="Sender's email password")
    parser.add_argument('--recipients', nargs='+', required=True, help="Recipient(s) email addresses")
    parser.add_argument('--smtp-server', default='smtp.office365.com', help="SMTP server (default: smtp.office365.com)")
    parser.add_argument('--smtp-port', type=int, default=587, help="SMTP server port (default: 587)")
    parser.add_argument('--openvas-username', required=True, help="OpenVAS username")
    parser.add_argument('--openvas-password', required=True, help="OpenVAS password")
    args = parser.parse_args()

    scan = Scan(username=args.openvas_username, password=args.openvas_password)
    scan.print_version()

    subnet_cidr = get_local_subnet_cidr()
    if not subnet_cidr:
        print("Error: Unable to retrieve local subnet.")
        sys.exit(1)

    hosts_list = generate_ip_list(subnet_cidr)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target_name = f"Local Subnet {subnet_cidr}"

    target_id = scan.get_target_id_by_name(target_name)
    if not target_id:
        target_id = scan.create_target(name=target_name, hosts_list=hosts_list)
        if not target_id:
            print(f"Error creating target {target_name}")
            sys.exit(1)

    task_id = scan.create_task(name=f"Local Subnet Scan {now}", target_id=target_id)
    if not task_id:
        print(f"Error creating task for {target_name}")
        sys.exit(1)

    task_response = scan.start_task(task_id)
    if not task_response:
        print(f"Error starting task {task_id}")
        sys.exit(1)

    report_id = scan.find_report_id_from_task_response(task_response)
    if not report_id:
        print("Error retrieving report ID")
        sys.exit(1)

    while not scan.is_task_finished(report_id):
        time.sleep(30)

    report_file_name = "report.pdf"
    scan.save_report_to_pdf(report_id, report_file_name)

    scan.send_report_via_email(
        report_file_name=report_file_name,
        subject="OpenVAS Scan Report",
        body="Here is your OpenVAS Scan Report.",
        sender=args.sender_email,
        recipients=args.recipients,
        password=args.sender_password,
        smtp_server=args.smtp_server,
        smtp_port=args.smtp_port
    )

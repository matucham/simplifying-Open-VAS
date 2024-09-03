import gvm
import netifaces
from gvm.protocols.latest import Gmp
from gvm.connections import UnixSocketConnection
from lxml import etree
import base64
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import ipaddress
from datetime import datetime

class Mail:

    def send_email(self, sender, recipients, password, msg):
        try:
            smtp_server = smtplib.SMTP('smtp.office365.com', 587)
            smtp_server.starttls()
            smtp_server.login(sender, password)
            smtp_server.sendmail(sender, recipients, msg.as_string())
            smtp_server.quit()
            print("Email sent successfully")
        except Exception as e:
            print(f"Error sending email: {e}")

    def create_msg(self, subject, body, sender, recipients):
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = ', '.join(recipients)
        msg.attach(MIMEText(body))
        return msg

    def add_attachment(self, attachment_path, msg):
        try:
            with open(attachment_path, "rb") as attachment:
                part = MIMEApplication(attachment.read(), Name=attachment_path)
            part['Content-Disposition'] = f'attachment; filename="{attachment_path}"'
            msg.attach(part)
            return msg
        except Exception as e:
            print(f"Error attaching file: {e}")
            return msg

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
        """Creates a task in GVM with the given name and target_id."""
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
        except etree.XMLSyntaxError as e:
            print(f"XML syntax error: {e}")
        except AttributeError as e:
            print(f"Error accessing XML attribute: {e}")
        except gvm.errors.GvmError as e:
            print(f"GVM error: {e}")
        except Exception as e:
            print(f"Error creating task: {e}")
        return None

    def create_target(self, name, hosts_list):
        """Creates a target in GVM with the given name and list of hosts."""
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
        except etree.XMLSyntaxError as e:
            print(f"XML syntax error: {e}")
        except AttributeError as e:
            print(f"Error accessing XML attribute: {e}")
        except gvm.errors.GvmError as e:
            print(f"GVM error: {e}")
        except Exception as e:
            print(f"Error creating target: {e}")
        return None

    def get_target_id_by_name(self, target_name):
        """Retrieves the target ID for a given target name."""
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

    def get_task_id(self, task_name):
        """Retrieves the task ID for a given task name."""
        try:
            response = self.gmp.get_tasks(filter_string=f"name={task_name}")
            root = etree.fromstring(response)
            name = root.find('./target/name').text
            if (target_name != name):
                print("Target not found.")
                return None
            task_element = root.find('.//task')
            if task_element is not None:
                task_id = task_element.get('id')
                return task_id
            else:
                print("Task not found.")
                return None
        except Exception as e:
            print(f"Error retrieving task ID: {e}")
            return None

    def start_task(self, task_id):
        """Starts a task in GVM with the given task ID."""
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
        """Finds the report ID from the task response."""
        try:
            root = etree.fromstring(task_response)
            report_id = root.find('.//report_id').text
            return report_id
        except Exception as e:
            print(f"Error finding report ID: {e}")
            return None

    def is_task_finished(self, report_id):
        """Checks if the task with the given report ID is finished."""
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
        """Saves the report with the given report ID to a PDF file."""
        try:
            report = self.gmp.get_report(report_id, report_format_id='c402cc3e-b531-11e1-9163-406186ea4fc5') # pdf format
            start_index = report.index('</report_format>')
            last_index = report.index('</report>')
            encoded_report_pdf = report[start_index + len('</report_format>'): last_index]
            decoded_bytes = base64.b64decode(encoded_report_pdf)
            with open(report_file_name, 'wb') as f:
                f.write(decoded_bytes)
            print(f"Report saved to {report_file_name}")
        except Exception as e:
            print(f"Error saving report to PDF: {e}")

    def send_report_via_email(self, report_file_name, subject, body, sender, recipients, password):
        """Sends the generated report via email."""
        mail = Mail()
        msg = mail.create_msg(subject, body, sender, recipients)
        msg = mail.add_attachment(report_file_name, msg)
        mail.send_email(sender, recipients, password, msg)

def get_local_subnet_cidr():
    """Returns the local subnet and mask in CIDR notation."""
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
    """Generates a list of IP addresses in the given subnet."""
    return [str(ip) for ip in ipaddress.IPv4Network(subnet)]

if __name__ == "__main__":
    scan = Scan(username="", password="") # here goes the username and password of the OpenVAS user
    scan.print_version()
    subnet_cidr = get_local_subnet_cidr()
    hosts_list = generate_ip_list(subnet_cidr)
    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    target_name = f"Local Subnet {subnet_cidr}"
    print(subnet_cidr)
    print(target_name)
    print(now_str)
    target_id = scan.get_target_id_by_name(target_name)
    if not target_id:
        target_id = scan.create_target(name=target_name, hosts_list=hosts_list)
        print(f"Target ID: {target_id}")
    if target_id:
        task_id = scan.create_task(name=f"Local Subnet Scan {now_str}", target_id=target_id)
        print(f"Task ID: {task_id}")
        if task_id:
            task_response = scan.start_task(task_id)
            #print(f"Task Response: {task_response}")
            if task_response:
                report_id = scan.find_report_id_from_task_response(task_response)
                print(f"Report ID: {report_id}")
                if report_id:
                    while not scan.is_task_finished(report_id):
                        time.sleep(30)
                    scan.save_report_to_pdf(report_id, "report.pdf")
                    scan.send_report_via_email(
                        report_file_name="report.pdf",
                        subject="OpenVAS Scan Report",
                        body="Here is your OpenVAS Scan Report!",
                        sender="", # here goes the email address of the sender
                        recipients=[""], # here goes the email address of the recipient
                        password="" # here goes the password of the sender
                    )

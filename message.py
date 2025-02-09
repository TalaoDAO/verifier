import smtplib
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formataddr
from email.mime.text import MIMEText
import logging
import json
logging.basicConfig(level=logging.INFO)

signature = '\r\n\r\n\r\nThe Talao/Altme team.\r\nhttps://talao.io/'
keys = json.load(open('keys.json'))
password = keys['smtp_password']  # used in smtp.py


def message(subject, to, messagetext):
	fromaddr = "relay@talao.io"
	toaddr = [to]
	msg = MIMEMultipart()
	msg['From'] = formataddr((str(Header('Altme', 'utf-8')), fromaddr))
	msg['To'] = ", ".join(toaddr)
	msg['Subject'] =  subject
	body = messagetext + signature
	msg.attach(MIMEText(body, 'plain'))

	# creates SMTP session
	s = smtplib.SMTP('smtp.gmail.com', 587)
	s.starttls()
	s.login(fromaddr, password)
	text = msg.as_string()

	# sending the mail
	try:
		s.sendmail(msg['from'],  msg["To"].split(","), text)
	except Exception:
		logging.error('sending mail')
		return
	s.quit()
	return True

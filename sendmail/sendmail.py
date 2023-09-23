#!/usr/bin/env python3

import smtplib
import dkim
from email.mime.text import MIMEText

sender = ""
receiver = ""
subject = "Subject"
message = "Message"

dkim_selector = ""
dkim_domain = ""
# openssl genrsa -out priv.pem 1024
# openssl rsa -in priv.pem -out pub.pub -pubout
dkim_privkey = """""".strip()

msg = MIMEText(message)

msg["Subject"] = subject
msg["From"] = sender
msg["To"] = receiver

dkim = dkim.sign(
  message=msg.as_bytes(),
  selector=dkim_selector.encode(),
  domain=dkim_domain.encode(),
  privkey=dkim_privkey.encode(),
  include_headers=[b"To", b"From", b"Subject"]
)

msg["DKIM-Signature"] = dkim[len("DKIM-Signature: "): ].decode()

s = smtplib.SMTP("example.com:25")
s.starttls()
s.ehlo()
s.set_debuglevel(1)
s.sendmail(sender, [receiver], msg.as_string())
s.quit()


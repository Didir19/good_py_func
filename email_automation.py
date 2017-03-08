import smtplib

from email.mime.image import MIMEImage
from email.mime.text import MIMEText
 
def email():
    # Create the container (outer) email message.
    msg = MIMEMultipart()
    msg['Subject'] = 'Mail TEST'
    # me == the sender's email address
    # family = the list of all recipients' email addresses
    msg['From'] = 'PIGBot@akamai.com'
    msg['To'] = 'egozlan@akamai.com, eshuster@akamai.com, abenisha@akamai.com'
    msg.preamble = 'Our TEST'

    # Assume we know that the image files are all in PNG format
    with open('/Users/abenisha/work/projects/smackdown/Flask-SocketIO-Chat-master/app/static/img/bot.png', 'rb') as fp:
        img = MIMEImage(fp.read())
    msg.attach(img)
    msg.attach(MIMEText('How Do You Do?'))
    # Send the email via our own SMTP server.
    s = smtplib.SMTP('smtp.akamai.com')
    s.send_message(msg)
    s.quit()
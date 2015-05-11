# *-* coding: utf-8 *-*
__author__ = 'milk'
__doc__ = """
    System module to perform mailing actions
"""
import smtplib

from mailer import Mailer, Message


def send_register_mail(user, pwd):
    message = Message()
    message.From = 'no-reply'
    message.Body = "Ваш пароль: %s" % pwd
    message.To = user['email']
    message.Subject = 'Регистрация в системе'
    try:
        sender.send(message)
        return True
    except (
        smtplib.SMTPAuthenticationError,
        smtplib.SMTPDataError,
        smtplib.SMTPConnectError,
        smtplib.SMTPRecipientsRefused,
        smtplib.SMTPSenderRefused,
        smtplib.SMTPResponseException,
        smtplib.SMTPServerDisconnected,
        smtplib.SMTPHeloError,
        smtplib.SMTPException
    ) as e:
        print(e)
        return False

sender = Mailer()
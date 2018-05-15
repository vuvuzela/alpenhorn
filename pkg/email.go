package pkg

import (
	"bytes"
	"crypto/tls"
	"html/template"
	"net"
	"net/mail"
	"net/smtp"

	"vuvuzela.io/alpenhorn/errors"
)

type SMTPRelay struct {
	Addr string
	Auth smtp.Auth
	From string

	SkipVerify bool
}

func (r *SMTPRelay) SendMail(to string, msg []byte) error {
	host, _, err := net.SplitHostPort(r.Addr)
	if err != nil {
		return err
	}

	client, err := smtp.Dial(r.Addr)
	if err != nil {
		return err
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); !ok {
		return errors.New("server does not support STARTTLS: %s", host)
	}
	config := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: r.SkipVerify,
	}
	if err := client.StartTLS(config); err != nil {
		return errors.Wrap(err, "SMTP StartTLS")
	}

	if r.Auth != nil {
		err := client.Auth(r.Auth)
		if err != nil {
			return errors.Wrap(err, "SMTP Auth")
		}
	}

	if err := client.Mail(r.From); err != nil {
		return nil
	}
	if err := client.Rcpt(to); err != nil {
		return errors.Wrap(err, "SMTP Rcpt")
	}
	w, err := client.Data()
	if err != nil {
		return errors.Wrap(err, "SMTP Data")
	}
	_, err = w.Write(msg)
	if err != nil {
		return errors.Wrap(err, "SMTP Write")
	}
	if err := w.Close(); err != nil {
		return errors.Wrap(err, "SMTP Close")
	}
	if err := client.Quit(); err != nil {
		return errors.Wrap(err, "SMTP Quit")
	}

	return nil
}

type verifyEmailData struct {
	From  string
	To    string
	Date  string
	Token string

	PKGAddr  string
	PKGIndex int
	NumPKGs  int
}

var verifyEmailTemplate = template.Must(template.New("verify_email").Parse(`Date: {{.Date}}
From: {{.From}}
To: {{.To}}
Subject: Vuvuzela email verification [{{.PKGIndex}} of {{.NumPKGs}}]
X-alpenhorn-token: {{.Token}}

To complete your Vuvuzela account registration, you must verify your
email address with each PKG server ({{.NumPKGs}} servers in total).

Run the following command in your Vuvuzela client to verify and register
your email address with {{.PKGAddr}}:

/register {{.PKGAddr}} {{.Token}}

You should have received a similar email from the other PKG servers.

--
Vuvuzela Private Messaging
https://vuvuzela.io
`))

func ParseTokenFromEmail(data []byte) (string, bool) {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return "", false
	}

	token := msg.Header.Get("X-alpenhorn-token")
	if token == "" {
		return "", false
	}
	return token, true
}

const express = require('express');
const nodemailer = require('nodemailer');
const fetch = require('node-fetch');

const app = express();

// PayPal sends the raw body for webhook signature verification, so we keep the raw buffer
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

const {
  PAYPAL_CLIENT_ID,
  PAYPAL_CLIENT_SECRET,
  PAYPAL_WEBHOOK_ID,
  PAYPAL_MODE, // "sandbox" or "live"
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
  FROM_EMAIL,
  PORT,
  SKIP_SIGNATURE_VERIFICATION // "true" = alleen voor testen met de PayPal Webhook Simulator, NIET gebruiken in productie
} = process.env;

const PAYPAL_BASE_URL = PAYPAL_MODE === 'live'
  ? 'https://api-m.paypal.com'
  : 'https://api-m.sandbox.paypal.com';

// --- Mailer setup ---
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT) || 587,
  secure: Number(SMTP_PORT) === 465,
  auth: { user: SMTP_USER, pass: SMTP_PASS }
});

// --- PayPal helpers ---
async function getPayPalAccessToken() {
  const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString('base64');
  const res = await fetch(`${PAYPAL_BASE_URL}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${auth}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: 'grant_type=client_credentials'
  });
  if (!res.ok) {
    throw new Error(`PayPal token request failed: ${res.status} ${await res.text()}`);
  }
  const data = await res.json();
  return data.access_token;
}

async function verifyWebhookSignature(headers, body, accessToken) {
  const verifyRes = await fetch(`${PAYPAL_BASE_URL}/v1/notifications/verify-webhook-signature`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      auth_algo: headers['paypal-auth-algo'],
      cert_url: headers['paypal-cert-url'],
      transmission_id: headers['paypal-transmission-id'],
      transmission_sig: headers['paypal-transmission-sig'],
      transmission_time: headers['paypal-transmission-time'],
      webhook_id: PAYPAL_WEBHOOK_ID,
      webhook_event: body
    })
  });
  const data = await verifyRes.json();
  return data.verification_status === 'SUCCESS';
}

async function getDisputeDetails(disputeId, accessToken) {
  const res = await fetch(`${PAYPAL_BASE_URL}/v1/customer/disputes/${disputeId}`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  if (!res.ok) {
    throw new Error(`Dispute lookup failed: ${res.status} ${await res.text()}`);
  }
  return res.json();
}

// --- Email content ---
const STORE_NAME = 'Halcyon Label';

// Per dispute-reden een eigen template. PayPal's reason-codes:
// https://developer.paypal.com/docs/api/customer-disputes/v1/#definition-reason
const TEMPLATES = {
  MERCHANDISE_OR_SERVICE_NOT_RECEIVED: (disputeId) => ({
    subject: `Ihre PayPal-Reklamation (${disputeId})`,
    text: `Guten Tag,

wir haben festgestellt, dass Sie über PayPal einen Konflikt mit dem Grund „Artikel nicht erhalten" (Item Not Received) zu Ihrer Bestellung eröffnet haben.

Wir möchten uns zunächst kurz bei Ihnen melden, um zu prüfen, ob dieser Konflikt zum jetzigen Zeitpunkt noch relevant ist.

Wurde Ihre Bestellung inzwischen zugestellt? Falls Sie Ihre Bestellung mittlerweile erhalten haben, bitten wir Sie höflich, den PayPal-Konflikt zu schließen. Wenn eine Bestellung inzwischen zugestellt wurde, ist es wichtig, dass der Status der Zahlung und des damit verbundenen Konflikts entsprechend aktualisiert wird.

Ein weiterhin offener Konflikt, obwohl die Bestellung bereits zugestellt wurde, kann unnötige Folgen haben. PayPal kann einen offenen Konflikt bei der Bewertung der Transaktion berücksichtigen. Dies kann unter Umständen zu einer Rückerstattung, einer Einschränkung der Zahlung oder weiteren Maßnahmen im Zusammenhang mit der Transaktion führen. Außerdem kann ein nicht mehr aktueller Konflikt die weitere Bearbeitung Ihrer Bestellung unnötig verzögern.

Haben Sie Ihre Bestellung noch nicht erhalten? Dann teilen Sie uns dies bitte mit. Wir helfen Ihnen gerne dabei, den Verbleib Ihrer Sendung zu überprüfen und gemeinsam eine passende Lösung zu finden.

Falls Ihre Bestellung inzwischen zugestellt wurde, bitten wir Sie, den Konflikt so schnell wie möglich bei PayPal zu schließen. Dadurch können unnötige Verzögerungen oder weitere Schritte im Rahmen des Konfliktverfahrens vermieden werden.

Vielen Dank für Ihre Mithilfe und Ihr Verständnis.

Mit freundlichen Grüßen
${STORE_NAME} Kundenservice`
  })
};

function buildDisputeEmail(dispute) {
  const disputeId = dispute.dispute_id;
  const reason = dispute.reason || 'ONKNOWN';
  const buyerEmail = dispute.disputed_transactions?.[0]?.buyer?.email;

  const template = TEMPLATES[reason];
  const { subject, text } = template
    ? template(disputeId)
    : {
        subject: `Betreft je bestelling — geschil ${disputeId}`,
        text: `Beste klant,

We hebben gezien dat er een geschil (${disputeId}) is geopend over je bestelling.
Reden: ${reason}

We nemen dit serieus en pakken het zo snel mogelijk op. Heb je nog vragen of aanvullende informatie, reply gerust op deze mail.

Met vriendelijke groet
${STORE_NAME}`
      };

  return { to: buyerEmail, subject, text };
}

// --- Webhook endpoint ---
app.post('/paypal/webhook', async (req, res) => {
  try {
    const accessToken = await getPayPalAccessToken();

    if (SKIP_SIGNATURE_VERIFICATION === 'true') {
      console.warn('LET OP: signature-verificatie is uitgeschakeld (alleen voor testen).');
    } else {
      const isValid = await verifyWebhookSignature(req.headers, req.body, accessToken);
      if (!isValid) {
        console.warn('Ongeldige webhook-signature ontvangen, genegeerd.');
        return res.status(400).send('Invalid signature');
      }
    }

    const event = req.body;
    console.log('Ontvangen event:', event.event_type);

    const disputeEvents = [
      'CUSTOMER.DISPUTE.CREATED',
      'CUSTOMER.DISPUTE.UPDATED',
      'CUSTOMER.DISPUTE.RESOLVED'
    ];

    if (disputeEvents.includes(event.event_type)) {
      const disputeId = event.resource?.dispute_id;
      const dispute = await getDisputeDetails(disputeId, accessToken);
      const email = buildDisputeEmail(dispute);

      if (!email.to) {
        console.warn(`Geen e-mailadres gevonden voor geschil ${disputeId}, mail niet verstuurd.`);
      } else {
        await transporter.sendMail({
          from: FROM_EMAIL,
          to: email.to,
          subject: email.subject,
          text: email.text
        });
        console.log(`Mail verstuurd naar ${email.to} voor geschil ${disputeId}`);
      }
    }

    // Always respond 200 fast so PayPal doesn't retry unnecessarily
    res.status(200).send('OK');
  } catch (err) {
    console.error('Fout bij verwerken webhook:', err);
    res.status(500).send('Server error');
  }
});

// Health check — handig om te testen of Railway de app live heeft staan
app.get('/', (req, res) => res.send('PayPal agent draait.'));

const port = PORT || 3000;
app.listen(port, () => console.log(`Server luistert op poort ${port}`));

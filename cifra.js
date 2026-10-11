#!/usr/bin/env node
// Cifra una pagina HTML e produce un lista.html che si apre solo con la password.
//
// Uso:
//   node cifra.js lista_originale.html "haha67"            -> crea lista.html
//   node cifra.js lista_originale.html "haha67" altro.html  -> crea altro.html
//
// IMPORTANTE: il file originale NON va caricato su GitHub, solo quello cifrato.

const fs = require("fs");
const crypto = require("crypto");

const [, , input, password, output = "lista.html"] = process.argv;

if (!input || !password) {
  console.error('Uso: node cifra.js <originale.html> "<password>" [output.html]');
  process.exit(1);
}

const ITERAZIONI = 600000;

const contenuto = fs.readFileSync(input);
const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);
const chiave = crypto.pbkdf2Sync(password, salt, ITERAZIONI, 32, "sha256");
const cifrario = crypto.createCipheriv("aes-256-gcm", chiave, iv);
const cifrato = Buffer.concat([
  cifrario.update(contenuto),
  cifrario.final(),
  cifrario.getAuthTag(), // la Web Crypto vuole il tag in coda ai dati
]);

const pagina = `<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gianlu</title>
</head>
<body>
  <p>Caricamento...</p>
  <script>
    (async function () {
      const SALT = "${salt.toString("base64")}";
      const IV = "${iv.toString("base64")}";
      const DATI = "${cifrato.toString("base64")}";
      const ITERAZIONI = ${ITERAZIONI};

      function daBase64(s) {
        return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); });
      }

      function tornaAlLogin(errore) {
        try {
          sessionStorage.removeItem("k");
          if (errore) sessionStorage.setItem("errore", "1");
        } catch (e) {}
        window.location.replace("index.html");
      }

      let password = null;
      try { password = sessionStorage.getItem("k"); } catch (e) {}
      if (!password) return tornaAlLogin(false);

      try {
        const base = await crypto.subtle.importKey(
          "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
        );
        const chiave = await crypto.subtle.deriveKey(
          { name: "PBKDF2", salt: daBase64(SALT), iterations: ITERAZIONI, hash: "SHA-256" },
          base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
        );
        const chiaro = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: daBase64(IV) }, chiave, daBase64(DATI)
        );
        document.open();
        document.write(new TextDecoder().decode(chiaro));
        document.close();
      } catch (e) {
        tornaAlLogin(true);
      }
    })();
  </script>
</body>
</html>
`;

fs.writeFileSync(output, pagina);
console.log("Creato " + output + " (" + pagina.length + " caratteri)");

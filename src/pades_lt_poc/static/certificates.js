// Tab Certificados: una card por firma con su cadena (respuesta de POST /certificates).

const ROLES = { end_entity: "Firmante", intermediate: "Intermedia", root: "Raíz" };
const SOURCES = {
  cms: ["cms", "Embebido en la firma (CMS)"],
  dss: ["dss", "Embebido en el DSS del PDF"],
  store: ["fuente", "No viene en el PDF: salió de la fuente de certificados"],
  aia: ["aia", "No viene en el PDF: se descargó de la URL AIA caIssuers"],
};

const inStoreChip = () => el("span", "chip in-store", "En la fuente");

// Las CAs se agregan a la fuente desde el reporte de inspección («Ver detalle»); acá sólo
// se indica si ya están. Cuando se agrega una, se marcan todas sus apariciones (la misma
// CA suele estar en varias cadenas: firma, sello y sello de documento).
document.addEventListener("store:added", (event) => {
  for (const title of document.querySelectorAll(`.cert-title[data-sha="${event.detail.sha256}"]`)) {
    if (!title.querySelector(".in-store")) title.append(inStoreChip());
  }
});

function certRow(cert, hooks) {
  const row = el("li");
  const info = el("div", "cert-info");

  const title = el("div", "cert-title");
  title.dataset.sha = cert.sha256_fingerprint;
  const [sourceLabel, sourceHelp] = SOURCES[cert.source] || [cert.source, ""];
  const source = el("span", `source${cert.source === "store" ? " from-store" : ""}`, sourceLabel);
  source.title = sourceHelp;
  title.append(el("span", "role", ROLES[cert.type]), el("span", "cn", cn(cert.subject)), source);
  if (cert.in_store) title.append(inStoreChip());

  const meta = el("div", "meta");
  meta.append(
    el("span", null, `Emisor: ${cn(cert.issuer)}${cert.self_signed ? " (autofirmado)" : ""}`),
    el("span", null, `Vigencia: ${date(cert.not_before)} – ${date(cert.not_after)}`),
    el("span", "mono", `Serie ${cert.serial_number}`),
  );
  info.append(title, meta);

  const inspect = el("button", "secondary");
  inspect.type = "button";
  inspect.append(icon("inspect"), "Ver detalle");
  inspect.setAttribute("aria-label", `Ver detalle de ${cn(cert.subject)} en la tab Inspección`);
  inspect.addEventListener("click", () => hooks.onInspect(cert.der_b64));

  const actions = el("div", "actions");
  actions.append(inspect, ...certActions(cert.der_b64, cert.subject, cert.serial_number, hooks.onStatus));
  row.append(info, actions);
  return row;
}

function chainList(certs, hooks) {
  const list = el("ol", "chain");
  list.append(...certs.map((c) => certRow(c, hooks)));
  return list;
}

function chainBadge(entry) {
  if (!entry.chain_complete) return badge("Cadena incompleta", "warn");
  if (entry.certificates.some((c) => c.source === "aia")) return badge("Completada por AIA", "warn");
  if (entry.certificates.some((c) => c.source === "store")) return badge("Completada con la fuente", "warn");
  return badge("Cadena completa", "ok");
}

function chainNotes(entry) {
  return (entry.aia_errors || []).map((msg) => el("p", "note", `AIA: ${msg}`));
}

function signatureChainCard(entry, hooks) {
  const article = el("article");
  const head = el("div", "card-head");
  head.append(
    el("h3", null, entry.field),
    el("span", "chip", entry.type === "DocTimeStamp" ? "Sello de documento" : "Firma"),
    el("span", "spacer"),
  );
  article.append(head);

  if (!entry.crypto_valid) {
    head.append(badge("Firma inválida", "bad"));
    article.append(el("p", "card-error", `${entry.error} — no se extraen certificados.`));
    return article;
  }
  head.append(badge("Firma válida", "ok"), chainBadge(entry));
  article.append(chainList(entry.certificates, hooks), ...chainNotes(entry));

  const ts = entry.signature_timestamp;
  if (ts) {
    const details = el("details");
    const summary = el("summary");
    summary.append(el("strong", null, "Sello de tiempo"));
    if (ts.crypto_valid) {
      summary.append(
        el("span", "mono", when(ts.time)),
        el("span", null, `· ${cn(ts.certificates[0].subject)}`),
        el("span", "toggle", `Cadena de la TSA (${ts.certificates.length})`),
      );
      details.append(summary, chainList(ts.certificates, hooks), ...chainNotes(ts));
    } else {
      summary.append(badge(`Inválido: ${ts.error}`, "bad"));
      details.append(summary);
    }
    article.append(details);
  }
  return article;
}

// Todos los certificados de la respuesta, sin repetir (la intermedia suele estar en varias cadenas).
function uniqueCertificates(data) {
  const seen = new Map();
  for (const entry of data.signatures) {
    const chains = [entry.certificates, entry.signature_timestamp?.certificates];
    for (const cert of chains.flat().filter(Boolean)) {
      if (!seen.has(cert.der_b64)) seen.set(cert.der_b64, { ...cert, foundIn: entry.field });
    }
  }
  return [...seen.values()];
}

// `hooks`: { onInspect(der_b64), onStatus(texto) }.
function renderCertificates(data, hooks) {
  const cards = el("div", "cards");
  cards.append(...data.signatures.map((entry) => signatureChainCard(entry, hooks)));
  return cards;
}

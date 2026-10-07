// /ui/certificado: un certificado suelto (archivo o texto pegado), con el mismo reporte
// que la tab Inspección de /ui/firmas. Lo último que se inspeccionó se guarda en el
// navegador ("certificado": {file} o {text}) y se vuelve a mostrar al volver a la página.

const form = $("#form");
const setStatus = (text) => { $("#status").textContent = text; };
let ticket = 0;

async function inspectCertificate({ file, text }) {
  const body = new FormData();
  if (file) body.append("crt", file);
  else body.append("b64", text);

  const current = ++ticket;
  const button = $("button[type=submit]", form);
  button.disabled = true;
  button.textContent = "Leyendo…";
  const out = $("#out");
  out.replaceChildren();
  try {
    const data = await postForm("/certificates/inspect", body);
    if (current === ticket) out.append(renderInspection(data.certificates, setStatus));
  } catch (error) {
    if (current === ticket) out.append(el("div", "error-box", `No se pudo leer el certificado: ${error.message}`));
  } finally {
    button.disabled = false;
    button.textContent = "Ver certificado";
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const file = form.crt.files[0];
  const text = form.b64.value.trim();
  if (!file && !text) return setStatus("Elegí un archivo o pegá el certificado");
  if (file && text) return setStatus("Usá el archivo o el texto, no los dos");
  setStatus("");
  const input = file ? { file } : { text };
  save("certificado", input);
  inspectCertificate(input);
});

$("#clear").addEventListener("click", () => {
  ticket++;
  form.reset();
  setStatus("");
  $("#out").replaceChildren();
  forget("certificado");
});

// Soltar un archivo sobre la zona lo carga en el input (el input sólo acepta drops sobre sí mismo).
const dropzone = $("#dropzone");
dropzone.addEventListener("dragover", (event) => {
  event.preventDefault();
  dropzone.classList.add("over");
});
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("over"));
dropzone.addEventListener("drop", (event) => {
  event.preventDefault();
  dropzone.classList.remove("over");
  if (event.dataTransfer.files.length) form.crt.files = event.dataTransfer.files;
});

async function restore() {
  const saved = await loadSaved("certificado");
  if (saved?.file instanceof Blob) restoreFileInput(form.crt, saved.file);
  else if (typeof saved?.text === "string") form.b64.value = saved.text;
  else return;
  inspectCertificate(saved);
}

setupThemeButton($("#theme"));
restore();

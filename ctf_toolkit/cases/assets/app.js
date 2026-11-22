"use strict";

const byId = (id) => document.getElementById(id);
const isTeam = document.body.dataset.mode === "team";
const apiRoot = new URL("api/", document.baseURI);
let state = null;
let current = null;
let selectionVersion = 0;
let selectionPending = false;
let analyzing = false;
let highlighted = null;
let editor = null;
let tab = "evidence";
let eventOffset = 0;
const selectedEvents = new Map();
const loadedEvents = new Map();
let liveRefresh = 0;

function node(tag, text, className) {
  const item = document.createElement(tag);
  if (text !== undefined) item.textContent = text;
  if (className) item.className = className;
  return item;
}

function button(text, action) {
  const item = node("button", text, "button secondary");
  item.type = "button";
  item.addEventListener("click", action);
  return item;
}

function status(message, error = false) {
  const box = byId("status");
  box.hidden = !message;
  box.textContent = message;
  box.classList.toggle("error", error);
}

function run(task) {
  return Promise.resolve().then(task).catch((error) => status(error.message, true));
}

function csrf() {
  const token = document.cookie.split("; ").find((pair) => pair.startsWith("csrftoken="));
  return token ? decodeURIComponent(token.slice(10)) : "";
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers);
  if (isTeam && options.method === "POST") headers.set("X-CSRFToken", csrf());
  const response = await fetch(new URL(path, apiRoot), { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error || "Request failed (" + response.status + ")");
    error.details = data;
    error.code = response.status;
    throw error;
  }
  return data;
}

function post(path, data, extra = {}) {
  return api(path, { method: "POST", body: JSON.stringify(data),
    headers: { "Content-Type": "application/json", ...extra } });
}

function writable() {
  return state !== null && state.role !== "viewer";
}

function activity(readOnly = false, label = "") {
  if (!state) return;
  const key = "ctftk-activity-" + state.case.case_id;
  let entries = [];
  try {
    const stored = JSON.parse(localStorage.getItem(key) || "[]");
    if (Array.isArray(stored)) entries = stored.filter((value) => typeof value.label === "string").slice(0, 20);
    if (label) {
      entries.unshift({ label, at: new Date().toISOString() });
      entries = entries.slice(0, 20);
      localStorage.setItem(key, JSON.stringify(entries));
    } else if (!readOnly) {
      localStorage.removeItem(key);
      entries = [];
    }
  } catch {
    if (label) entries = [{ label, at: new Date().toISOString() }];
  }
  byId("history").replaceChildren(...entries.map((entry) => {
    const time = new Date(entry.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    return node("li", entry.label + " · " + time);
  }));
}

function artifactName(id) {
  return state.artifacts.find((item) => item.id === id)?.label || id;
}

function tree() {
  const descendants = new Map();
  for (const artifact of state.artifacts) {
    const group = descendants.get(artifact.parent_id) || [];
    group.push(artifact);
    descendants.set(artifact.parent_id, group);
  }
  const list = byId("artifact-list");
  const items = document.createDocumentFragment();
  const stack = (descendants.get(null) || []).slice().reverse().map((entry) => [entry, 0]);
  while (stack.length) {
    const [artifact, depth] = stack.pop();
    const row = node("li");
    const select = node("button");
    select.type = "button";
    select.className = ["", "child", "grandchild", "nested"][Math.min(3, depth)];
    select.setAttribute("aria-pressed", String(current?.id === artifact.id));
    select.dataset.artifact = artifact.id;
    select.append(node("span", depth ? "↳" : "▱", "artifact-icon"), node("span", artifact.label));
    select.firstChild.setAttribute("aria-hidden", "true");
    select.addEventListener("click", () => run(() => openArtifact(artifact.id)));
    row.append(select);
    items.append(row);
    const children = descendants.get(artifact.id) || [];
    for (let index = children.length - 1; index >= 0; index -= 1) {
      stack.push([children[index], depth + 1]);
    }
  }
  list.replaceChildren(items);
  byId("artifact-count").textContent = state.artifacts.length;
  byId("empty-tree").hidden = state.artifacts.length > 0;
}

function choices(id, options, placeholder) {
  const select = byId(id);
  const existing = select.value;
  const items = options.map((item) => new Option(item.label, item.id));
  if (placeholder) items.unshift(new Option(placeholder, ""));
  select.replaceChildren(...items);
  if (items.some((item) => item.value === existing)) select.value = existing;
}

function syncControls() {
  byId("team-home").hidden = !isTeam;
  byId("team-tab").hidden = !isTeam || state.role !== "owner";
  byId("upload-label").hidden = !writable();
  byId("upload").disabled = !writable();
  for (const item of document.querySelectorAll("[data-edit]")) {
    if (item.id !== "note-form") item.hidden = !writable();
  }
  choices("comparison", state.artifacts.filter((item) => item.id !== current?.id));
  choices("timeline-input", state.artifacts);
  choices("timeline-source", state.artifacts, "All sources");
}

async function refresh() {
  const next = await api("state");
  if (state && next.seq < state.seq) return state;
  state = next;
  byId("case-title").textContent = state.case.title;
  document.title = state.case.title + " · CTF Toolkit";
  tree();
  syncControls();
  renderNotes();
  activity(true);
  if (!current && !selectionPending && state.artifacts.length) {
    await openArtifact(state.artifacts[0].id, 0, null, false);
  }
  return state;
}

function tabTo(next) {
  tab = next;
  for (const area of document.querySelectorAll(".view")) area.hidden = area.id !== next;
  for (const nav of document.querySelectorAll("[data-tab]")) {
    if (nav.dataset.tab === next) nav.setAttribute("aria-current", "page");
    else nav.removeAttribute("aria-current");
  }
}

function hexDump(pre, preview, range = null) {
  const fragment = document.createDocumentFragment();
  const ranges = Array.isArray(range) ? range : range ? [range] : [];
  for (let cursor = 0; cursor < preview.hex.length / 2; cursor += 16) {
    const address = preview.offset + cursor;
    fragment.append(node("span", address.toString(16).padStart(8, "0") + "  ", "address"));
    for (let column = 0; column < 16 && 2 * (cursor + column) < preview.hex.length; column += 1) {
      const value = preview.hex.slice(2 * (cursor + column), 2 * (cursor + column + 1));
      const where = address + column;
      if (ranges.some((part) => where >= part.start && where < part.stop)) fragment.append(node("mark", value));
      else fragment.append(document.createTextNode(value));
      fragment.append(document.createTextNode(" "));
    }
    fragment.append(document.createTextNode("\n"));
  }
  pre.replaceChildren(fragment);
}

function syncArtifactActions() {
  const preview = current?.preview;
  const waiting = selectionPending || !preview;
  byId("artifact-view").setAttribute("aria-busy", String(selectionPending));
  for (const id of ["preview-recipe", "save-recipe", "rank-caesar", "compare"]) {
    byId(id).disabled = waiting;
  }
  for (const id of ["parent", "trace-source", "trace-root", "bookmark"]) {
    const el = byId(id);
    if (el) el.disabled = selectionPending;
  }
  byId("analyze").disabled = waiting || analyzing;
  byId("download-artifact").hidden = state?.role !== "owner" || waiting;
  byId("prev-bytes").disabled = waiting || preview.offset === 0;
  byId("next-bytes").disabled = waiting || preview.offset + preview.hex.length / 2 >= preview.size;
}

function drawPreview() {
  const preview = current?.preview;
  const dump = byId("byte-data");
  byId("window").textContent = preview
    ? preview.offset + "–" + (preview.offset + preview.hex.length / 2) + " / " + preview.size : "Unavailable";
  if (!preview) dump.textContent = "This review package contains metadata for this artifact.";
  else if (!preview.hex.length) dump.textContent = "No bytes in this window.";
  else if (byId("byte-view").value === "text") dump.textContent = preview.text;
  else hexDump(dump, preview, highlighted);
}

function sectionLabel(section) {
  if (section.start !== undefined) {
    return section.name + " · bytes " + section.start + "–" + section.stop;
  }
  return section.name + " · header " + section.header_offset + " · " + section.size + " B";
}

async function openArtifact(id, offset = 0, range = null, navigate = true) {
  if (navigate) tabTo("evidence");
  const request = ++selectionVersion;
  selectionPending = true;
  syncArtifactActions();
  let next;
  try {
    next = await api("artifact/" + id + "?offset=" + offset);
  } finally {
    if (request === selectionVersion) {
      selectionPending = false;
      syncArtifactActions();
    }
  }
  if (request !== selectionVersion) return;
  if (next.id !== current?.id) {
    byId("compare-panel").hidden = true;
    byId("recipe-result").replaceChildren();
    byId("caesar-result").replaceChildren();
  }
  current = next;
  highlighted = range;
  if (range) byId("byte-view").value = "hex";
  byId("empty-evidence").hidden = true;
  byId("artifact-view").hidden = false;
  byId("artifact-name").textContent = next.label;
  const report = next.report;
  byId("artifact-kind").textContent = report
    ? report.format + " · " + report.confidence
      + (report.encodings.length ? " · " + report.encoding_status + " " + report.encodings.join(" / ") : "")
    : "Pending triage";
  byId("artifact-meta").textContent = next.size + " B · SHA-256 " + next.digest;
  byId("parent").hidden = !next.parent_id;
  byId("download-artifact").href = new URL("artifact/" + next.id + "/download", apiRoot);
  byId("range-start").value = range?.start ?? offset;
  byId("range-stop").value = range?.stop ?? Math.min(next.size, offset + 1);
  byId("range-start").max = next.size;
  byId("range-stop").max = next.size;
  const issues = report?.issues || [];
  byId("issues").hidden = !issues.length;
  byId("issue-list").replaceChildren(...issues.map((item) => node("li", item)));
  const sections = report?.sections || [];
  byId("structure").hidden = !sections.length;
  byId("sections").replaceChildren(...sections.map((section) => {
    const item = node("li");
    item.append(button(sectionLabel(section), () => run(() => {
      const start = section.start ?? section.header_offset;
      const stop = section.stop ?? Math.min(current.size, start + 30);
      return openArtifact(id, start, { start, stop });
    })));
    return item;
  }));
  drawPreview();
  syncArtifactActions();
  tree();
  syncControls();
}

function selectedRange() {
  return { start: Number(byId("range-start").value), stop: Number(byId("range-stop").value) };
}

function query(values) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== null && value !== "" && value !== undefined) params.set(key, String(value));
  }
  return params.toString();
}


function drawRecipe(result) {
  const destination = byId("recipe-result");
  destination.replaceChildren(...result.steps.map((step, index) => {
    const section = node("section", undefined, "result-step");
    section.append(node("strong", (index + 1) + ". " + step.operation));
    for (const [label, value] of [["Input", step.input], ["Output", step.output]]) {
      const view = node("pre", value.text.includes("\uFFFD") ? value.hex : value.text);
      section.append(node("p", label + " · " + value.size + " B", "hint"), view);
    }
    section.append(node("p", "SHA-256 " + step.sha256, "hint mono"));
    return section;
  }));
}

function drawComparison(result) {
  byId("compare-panel").hidden = false;
  byId("compare-description").textContent =
    result.differences.length + " differing regions" + (result.partial ? " in the displayed byte windows" : "");
  const columns = [];
  for (const [name, item] of [["left", result.left], ["right", result.right]]) {
    const column = node("div", undefined, "compare-side");
    column.append(node("h4", item.label));
    const dump = node("pre", undefined, "dump");
    const regions = result.differences.map((diff) => ({ start: diff[name][0], stop: diff[name][1] }));
    hexDump(dump, item.preview, regions);
    column.append(dump);
    const structure = node("ul", undefined, "compare-structure");
    structure.replaceChildren(...result.structures[name].map((section) => node("li", sectionLabel(section))));
    column.append(structure);
    columns.push(column);
  }
  byId("compare-data").replaceChildren(...columns);
  byId("diff-list").replaceChildren(...result.differences.slice(0, 80).map((diff) =>
    node("li", diff.kind + " · A " + diff.left.join("–") + " · B " + diff.right.join("–"))
  ));
}

function utcTime(event) {
  if (event.seconds === null) return event.original_time + " · offset unknown";
  const clock = new Date(event.seconds * 1000).toISOString().slice(0, 19);
  const fraction = event.precision ? "." + String(event.nanos).padStart(9, "0").slice(0, event.precision) : "";
  return clock.replace("T", " ") + fraction + "Z";
}

async function openEvent(entry) {
  const range = entry.event.source;
  return openArtifact(entry.artifact_id, range.start, { start: range.start, stop: range.stop });
}

async function renderTimeline(append = false) {
  if (!append) {
    eventOffset = 0;
    loadedEvents.clear();
    selectedEvents.clear();
    byId("events").replaceChildren();
  }
  const range = {};
  for (const [key, field] of [["start", "timeline-start"], ["stop", "timeline-stop"]]) {
    if (byId(field).value) range[key] = Math.floor(new Date(byId(field).value + "Z").getTime() / 1000);
  }
  const rows = await api("timeline?" + query({ artifact: byId("timeline-source").value, offset: eventOffset, ...range }));
  for (const entry of rows) {
    loadedEvents.set(entry.id, entry);
    const row = node("tr");
    const checkbox = node("input");
    checkbox.type = "checkbox";
    checkbox.disabled = !writable();
    checkbox.setAttribute("aria-label", "Select " + entry.event.message);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) selectedEvents.set(entry.id, entry);
      else selectedEvents.delete(entry.id);
    });
    const chosen = node("td");
    chosen.append(checkbox);
    const sourceCell = node("td");
    const source = entry.event.source;
    const label = artifactName(entry.artifact_id) + " · " + source.kind + " " + source.number;
    sourceCell.append(button(label, () => run(() => openEvent(entry))));
    row.append(chosen, node("td", utcTime(entry.event)), node("td", entry.event.message), sourceCell);
    byId("events").append(row);
  }
  if (!eventOffset && !rows.length) {
    const cell = node("td", "No events match this view.");
    cell.colSpan = 4;
    const row = node("tr");
    row.append(cell);
    byId("events").append(row);
  }
  eventOffset += rows.length;
  byId("more-events").hidden = rows.length !== 200;
}

function noteGroups() {
  const grouped = new Map();
  for (const note of state.notes) {
    const matches = grouped.get(note.note_id) || [];
    matches.push(note);
    grouped.set(note.note_id, matches);
  }
  return grouped;
}

function noteAnchorLabel(anchor) {
  if (anchor.kind === "event") {
    return loadedEvents.get(anchor.id)?.event.message || "Timeline event";
  }
  const label = artifactName(anchor.id);
  return anchor.kind === "bytes" ? label + " · bytes " + anchor.start + "–" + anchor.stop : label;
}

async function showAnchor(anchor) {
  if (anchor.kind === "event") {
    const record = loadedEvents.get(anchor.id) || await api("event/" + anchor.id);
    await openEvent(record);
  } else {
    const range = anchor.kind === "bytes" ? { start: anchor.start, stop: anchor.stop } : null;
    await openArtifact(anchor.id, range?.start || 0, range);
  }
}

function beginNote(anchors, notes = []) {
  if (!writable()) return;
  editor = { anchors, noteId: notes[0]?.note_id, bases: notes.map((item) => item.id) };
  byId("note-form").hidden = false;
  byId("note-body").value = notes.length === 1 ? notes[0].body : "";
  byId("note-heading").textContent = notes.length > 1 ? "Resolve note conflict" : notes.length ? "Edit note" : "New note";
  byId("note-context").textContent = anchors.map(noteAnchorLabel).join(" · ");
  tabTo("notes");
  byId("note-body").focus();
}

function renderNotes() {
  const result = [];
  for (const versions of noteGroups().values()) {
    const card = node("article", undefined, "note");
    if (versions.length > 1) card.append(node("h3", versions.length + " concurrent revisions"));
    for (const version of versions) {
      const detail = node("div", undefined, versions.length > 1 ? "conflict-copy" : "");
      const actor = version.imported_by ? version.author + " · imported by " + version.imported_by : version.author;
      detail.append(node("p", actor, "muted"), node("p", version.body, "body"));
      const anchors = node("div", undefined, "action-row");
      for (const anchor of version.anchor) {
        anchors.append(button(noteAnchorLabel(anchor), () => run(() => showAnchor(anchor))));
      }
      detail.append(anchors);
      card.append(detail);
    }
    if (writable()) {
      const action = node("div", undefined, "action-row");
      action.append(button(versions.length > 1 ? "Resolve" : "Edit",
                           () => beginNote(versions[0].anchor, versions)));
      card.append(action);
    }
    result.push(card);
  }
  if (!result.length) result.push(node("p", "No notes saved for this case.", "muted"));
  byId("note-list").replaceChildren(...result);
}

async function saveDraft() {
  const body = byId("note-body").value;
  const payload = { body, anchors: editor.anchors, note_id: editor.noteId, bases: editor.bases };
  const revisions = editor.bases.slice().sort();
  const fingerprint = JSON.stringify(payload);
  if (editor.fingerprint !== fingerprint) {
    editor.fingerprint = fingerprint;
    editor.requestId = crypto.randomUUID().replaceAll("-", "");
  }
  const header = { "Idempotency-Key": editor.requestId };
  if (editor.noteId) header["If-Match"] = '"' + revisions.join(".") + '"';
  try {
    await post("notes", payload, header);
  } catch (error) {
    if (error.code !== 412) throw error;
    const replacement = error.details.current;
    await refresh();
    const buttonLabel = "Review " + replacement.length + " current revision" + (replacement.length === 1 ? "" : "s");
    const next = button(buttonLabel, () => {
      editor.bases = replacement.map((item) => item.id);
      const extra = replacement.map((item) => item.author + ": " + item.body).join("\n\n");
      byId("note-context").textContent = extra;
      status("Current revisions loaded. Edit your draft before saving.");
    });
    status("This note changed while you were editing. Your draft is still here.", true);
    byId("status").append(document.createTextNode(" "), next);
    return;
  }
  editor = null;
  byId("note-form").hidden = true;
  byId("note-body").value = "";
  activity(false, "Note saved");
  await refresh();
  status("Note saved.");
}

async function renderMembers() {
  const members = await api("team/members");
  byId("members").replaceChildren(...members.map((member) => {
    const row = node("div", undefined, "member");
    row.append(node("span", member.user + " · " + member.role));
    if (member.role !== "owner") {
      row.append(button("Remove access", () => run(async () => {
        await post("team/revoke", { user: member.user });
        await renderMembers();
        status("Access removed for " + member.user + ".");
      })));
    }
    return row;
  }));
}


function subscribe(seq) {
  const stream = new EventSource(new URL("updates?after=" + seq, apiRoot));
  stream.onopen = () => { byId("connection").textContent = "Live · connected"; };
  stream.onerror = () => { byId("connection").textContent = "Live · reconnecting"; };
  stream.addEventListener("unavailable", () => {
    byId("connection").textContent = "Live · access ended";
    stream.close();
  });
  stream.onmessage = () => {
    window.clearTimeout(liveRefresh);
    liveRefresh = window.setTimeout(() => run(async () => {
      await refresh();
      if (tab === "timeline" && selectedEvents.size === 0) await renderTimeline();
    }), 80);
  };
}

byId("upload").addEventListener("change", (event) => run(async () => {
  const file = event.target.files[0];
  if (!file) return;
  event.target.value = "";
  if (file.size > 8 * 1024 * 1024) throw new Error("Browser uploads are limited to 8 MiB.");
  status("Importing evidence…");
  const saved = await api("import", {
    method: "POST", body: file,
    headers: { "Content-Type": "application/octet-stream", "X-Artifact-Name": encodeURIComponent(file.name) },
  });
  activity(false, "File imported");
  await refresh();
  await openArtifact(saved.id);
  status("Evidence imported.");
}));

for (const control of document.querySelectorAll("[data-tab]")) {
  control.addEventListener("click", () => run(async () => {
    tabTo(control.dataset.tab);
    if (tab === "timeline") await renderTimeline();
    if (tab === "team") await renderMembers();
  }));
}
byId("verify").addEventListener("click", () => run(async () => {
  status("Checking evidence and replaying saved operations…");
  const result = await api("verify?replay=true");
  status(result.ok ? result.checked_blobs + " evidence objects verified · " + result.replayed_runs + " runs replayed"
    : result.errors.join(" · "), !result.ok);
}));
byId("clear-history").addEventListener("click", () => activity());
byId("analyze").addEventListener("click", () => run(async () => {
  const id = current.id;
  const request = selectionVersion;
  analyzing = true;
  syncArtifactActions();
  status("Reading file structure…");
  try {
    const result = await post("analyze", { artifact: id });
    activity(false, result.status === "partial" ? "Triage finished with limits" : "Triage completed");
    await refresh();
    if (request === selectionVersion) await openArtifact(id, 0, null, false);
    status(result.inspected + " artifacts inspected · " + result.issues + " issues");
  } finally {
    analyzing = false;
    syncArtifactActions();
  }
}));
byId("parent").addEventListener("click", () => run(() => openArtifact(current.parent_id)));
byId("byte-view").addEventListener("change", drawPreview);
byId("prev-bytes").addEventListener("click", () => run(() => openArtifact(current.id, Math.max(0, current.preview.offset - 4096))));
byId("next-bytes").addEventListener("click", () => run(() => openArtifact(current.id, current.preview.offset + 4096)));
byId("trace-source").addEventListener("click", () => run(async () => {
  const region = await api("artifact/" + current.id + "/source?" + query(selectedRange()));
  const from = region.start ?? region.header_offset ?? 0;
  const selection = region.stop !== undefined ? { start: from, stop: region.stop } : null;
  await openArtifact(region.artifact_id, from, selection);
  if (region.kind === "zip_member") status("ZIP member " + region.name + " · local header at byte " + from + ".");
  else if (region.kind === "gzip_stream") status("Compressed source stream shown.");
  else if (region.kind === "codec") status("Transformation source shown.");
  else status("Source bytes highlighted.");
}));
if (byId("trace-root")) {
  byId("trace-root").addEventListener("click", () => run(async () => {
    const region = await api("artifact/" + current.id + "/source?" + query({ ...selectedRange(), root: "true" }));
    const from = region.start ?? region.header_offset ?? 0;
    const selection = region.stop !== undefined ? { start: from, stop: region.stop } : null;
    await openArtifact(region.artifact_id, from, selection);
    const hops = (region.hops || []).length;
    status("Root evidence highlighted" + (hops ? " (" + hops + " hops)" : "") + ".");
  }));
}
byId("bookmark").addEventListener("click", () => {
  const bounds = selectedRange();
  if (bounds.start >= bounds.stop || bounds.start < 0 || bounds.stop > current.size) {
    status("Choose a nonempty range within the artifact.", true);
    return;
  }
  beginNote([{ kind: "bytes", id: current.id, ...bounds }]);
});
byId("preview-recipe").addEventListener("click", () => run(async () => {
  const request = selectionVersion;
  const result = await post("recipe", { artifact: current.id, recipe: byId("recipe").value, preview: true });
  if (request !== selectionVersion) return;
  drawRecipe(result);
  status("Recipe preview ready.");
}));
byId("save-recipe").addEventListener("click", () => run(async () => {
  const id = current.id;
  const request = selectionVersion;
  const result = await post("recipe", { artifact: id, recipe: byId("recipe").value });
  activity(false, "Recipe branch saved");
  await refresh();
  if (request === selectionVersion) await openArtifact(result.artifacts.at(-1), 0, null, false);
  status("Branch saved · SHA-256 " + result.output_sha256);
}));
byId("compare").addEventListener("click", () => run(async () => {
  const other = byId("comparison").value;
  if (!other) throw new Error("Choose a second artifact.");
  const result = await api("compare?" + query({ left: current.id, right: other, offset_a: current.preview?.offset }));
  drawComparison(result);
  byId("compare-panel").scrollIntoView({ block: "nearest" });
}));
byId("close-compare").addEventListener("click", () => { byId("compare-panel").hidden = true; });
byId("rank-caesar").addEventListener("click", () => run(async () => {
  const result = await api("caesar?" + query({ artifact: current.id, lang: byId("caesar-lang").value }));
  const children = [node("p", result.scoring, "hint")];
  if (result.limited_evidence) children.push(node("p", "Short sample · limited evidence", "hint"));
  for (const candidate of result.candidates) {
    const card = node("div", undefined, "result-step");
    card.append(node("strong", "Shift " + candidate.shift + " · " + candidate.score), node("pre", candidate.text));
    children.push(card);
  }
  byId("caesar-result").replaceChildren(...children);
}));
byId("timeline-index").addEventListener("submit", (event) => {
  event.preventDefault();
  run(async () => {
    const result = await post("timeline", {
      artifact: byId("timeline-input").value, profile: byId("timeline-profile").value,
      timezone: byId("timeline-zone").value.trim() || null,
    });
    await renderTimeline();
    status(result.count + " events · " + result.status + (result.issues.length ? " · " + result.issues.join(" · ") : ""));
  });
});
byId("timeline-filter").addEventListener("submit", (event) => {
  event.preventDefault();
  run(() => renderTimeline());
});
byId("more-events").addEventListener("click", () => run(() => renderTimeline(true)));
byId("correlate").addEventListener("click", () => {
  if (!selectedEvents.size || selectedEvents.size > 8) {
    status("Select 1–8 events before adding a note.", true);
    return;
  }
  beginNote([...selectedEvents.keys()].map((id) => ({ kind: "event", id })));
});
byId("note-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run(saveDraft);
});
byId("cancel-note").addEventListener("click", () => {
  editor = null;
  byId("note-form").hidden = true;
});
byId("invite-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run(async () => {
    const result = await post("team/invite", { role: byId("invite-role").value });
    byId("invite-result").hidden = false;
    byId("invite-url").value = result.url;
    byId("invite-url").select();
    status("Invitation ready · valid for " + result.expires_in_hours + " hours.");
  });
});
run(async () => {
  await refresh();
  if (isTeam) subscribe(state.seq);
});

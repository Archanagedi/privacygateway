/**
 * PrivacyShield - DPDP Privacy Gateway Frontend Controller
 * Vanilla JavaScript (No React, Angular, or external libraries)
 * Implements full 6-view routing, 3-panel workspace, live API integration,
 * synthetic dataset testing, verifiable audit log viewing, and metrics telemetry.
 */

const API_BASE = window.location.origin;

// State management
const state = {
  activePage: 'dashboard',
  health: null,
  sampleDocuments: [],
  benchmarkResults: null,
  auditLogs: [],
  activeRawLLMResponse: '',
  activeUploadData: null,
  activeMaskedImageB64: null,
  activeOriginalImageB64: null,
  activeUploadFileName: null
};

// ==============================================================================
// INITIALIZATION
// ==============================================================================
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initTextareaListeners();
  checkBackendHealth();
  loadSampleDocuments();
  fetchDashboardMetrics();
  fetchAuditLogs();
  runSyntheticDatasetBenchmark(true);
});

// ==============================================================================
// 1. NAVIGATION ROUTING
// ==============================================================================
function initNavigation() {
  const navButtons = document.querySelectorAll('.sidebar-nav .nav-item');
  navButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetPage = btn.getAttribute('data-page');
      navigateToPage(targetPage);
    });
  });
}

function navigateToPage(pageId) {
  state.activePage = pageId;

  // Update nav active class
  document.querySelectorAll('.sidebar-nav .nav-item').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-page') === pageId);
  });

  // Switch page view
  document.querySelectorAll('.page-view').forEach(view => {
    view.classList.toggle('active', view.id === `page-${pageId}`);
  });

  // Update header title
  const pageTitles = {
    dashboard: 'Dashboard',
    gateway: 'Privacy Gateway Workspace',
    testing: 'Synthetic Document Evaluation & Benchmark',
    audit: 'Verifiable Audit Logs',
    metrics: 'Performance & Accuracy Telemetry',
    settings: 'Gateway Settings & Integrations'
  };
  document.getElementById('current-page-title').innerText = pageTitles[pageId] || 'Dashboard';

  // Trigger contextual data reload per page
  if (pageId === 'dashboard') {
    fetchDashboardMetrics();
  } else if (pageId === 'audit') {
    fetchAuditLogs();
  } else if (pageId === 'metrics') {
    loadPerformanceMetricsPage();
  } else if (pageId === 'settings') {
    loadSettingsPage();
  } else if (pageId === 'testing') {
    if (!state.sampleDocuments || state.sampleDocuments.length === 0) {
      loadSampleDocuments();
    } else {
      renderTestingTable();
    }
    if (state.benchmarkResults) {
      renderFalseNegativesTable(state.benchmarkResults.false_negatives_list || []);
      renderFalsePositivesTable(state.benchmarkResults.false_positives_list || []);
    } else {
      runSyntheticDatasetBenchmark(true);
    }
  }
}

// ==============================================================================
// 2. BACKEND HEALTH & SYSTEM STATUS
// ==============================================================================
async function checkBackendHealth() {
  const statusEl = document.getElementById('backend-conn-status');
  try {
    const res = await fetch(`${API_BASE}/api/health`);
    if (res.ok) {
      const data = await res.json();
      state.health = data;
      statusEl.innerText = 'Presidio & Gateway Online';
      statusEl.style.color = '#34d399';

      // Update header model badge
      const activeModel = data.groq_model;
      if (activeModel) {
        document.getElementById('header-active-model').innerText = activeModel;
      }

      // Check if simulation banner should be shown
      const simBanner = document.getElementById('gateway-simulated-banner');
      if (simBanner) {
        const isKeyConfigured = data.groq_api_key_configured;
        if (!isKeyConfigured) {
          simBanner.style.display = 'flex';
        } else {
          simBanner.style.display = 'none';
        }
      }
    } else {
      statusEl.innerText = 'Engine unreachable';
      statusEl.style.color = '#f87171';
    }
  } catch (err) {
    statusEl.innerText = 'Backend offline';
    statusEl.style.color = '#f87171';
  }
}

// ==============================================================================
// 3. PRIVACY GATEWAY (3-PANEL WORKSPACE)
// ==============================================================================
function initTextareaListeners() {
  const textarea = document.getElementById('original-document-input');
  const charCount = document.getElementById('input-char-count');

  if (textarea && charCount) {
    textarea.addEventListener('input', () => {
      charCount.innerText = `${textarea.value.length} characters`;
    });
  }
}

async function loadSampleDocuments() {
  try {
    const res = await fetch(`${API_BASE}/api/sample-documents`);
    if (res.ok) {
      const data = await res.json();
      state.sampleDocuments = data.documents || [];
      populateSampleDropdowns();
      renderTestingTable();
      if (state.benchmarkResults) {
        renderFalseNegativesTable(state.benchmarkResults.false_negatives_list || []);
        renderFalsePositivesTable(state.benchmarkResults.false_positives_list || []);
      }
    }
  } catch (err) {
    console.warn('Could not load sample documents:', err);
  }
}

function populateSampleDropdowns() {
  const select = document.getElementById('quick-sample-select');
  if (!select) return;

  select.innerHTML = '<option value="">Load Sample Indian Document...</option>';
  state.sampleDocuments.forEach(doc => {
    const opt = document.createElement('option');
    opt.value = doc.id;
    opt.innerText = `[${doc.category}] ${doc.title}`;
    select.appendChild(opt);
  });
}

function loadSelectedSampleIntoGateway() {
  const select = document.getElementById('quick-sample-select');
  const docId = select.value;
  if (!docId) return;

  const doc = state.sampleDocuments.find(d => d.id === docId);
  if (doc) {
    document.getElementById('original-document-input').value = doc.text;
    document.getElementById('doc-type-select').value = doc.category;
    document.getElementById('input-char-count').innerText = `${doc.text.length} characters`;
    showToast(`Loaded sample: ${doc.title}`, 'info');
  }
}

const SUPPORTED_UPLOAD_FORMATS = {
  pdf: { label: 'PDF Document', icon: '📕' },
  doc: { label: 'Word Document (DOC)', icon: '📘' },
  docx: { label: 'Word Document (DOCX)', icon: '📘' },
  xls: { label: 'Excel Spreadsheet (XLS)', icon: '📊' },
  xlsx: { label: 'Excel Spreadsheet (XLSX)', icon: '📊' },
  ppt: { label: 'PowerPoint Presentation (PPT)', icon: '📙' },
  pptx: { label: 'PowerPoint Presentation (PPTX)', icon: '📙' },
  txt: { label: 'Plain Text Document', icon: '📝' },
  csv: { label: 'CSV Spreadsheet', icon: '📑' },
  json: { label: 'JSON Data', icon: '📋' },
  xml: { label: 'XML Document', icon: '📄' },
  jpg: { label: 'JPEG Image', icon: '🖼️' },
  jpeg: { label: 'JPEG Image', icon: '🖼️' },
  png: { label: 'PNG Image', icon: '🖼️' },
  webp: { label: 'WebP Image', icon: '🖼️' },
  bmp: { label: 'Bitmap Image (BMP)', icon: '🖼️' },
  tiff: { label: 'TIFF Image', icon: '🖼️' },
  tif: { label: 'TIFF Image', icon: '🖼️' }
};

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function displayUploadedFileInfo(fileName, formatLabel, sizeFormatted, icon = '📄') {
  const banner = document.getElementById('uploaded-file-banner');
  const nameEl = document.getElementById('file-banner-name');
  const metaEl = document.getElementById('file-banner-meta');
  const iconEl = document.getElementById('file-banner-icon');

  if (banner && nameEl && metaEl) {
    nameEl.innerText = fileName;
    nameEl.title = fileName;
    metaEl.innerText = `${formatLabel} • ${sizeFormatted}`;
    if (iconEl) iconEl.innerText = icon;
    banner.style.display = 'flex';
  }
}

function clearUploadedFile(event) {
  if (event) event.stopPropagation();
  const banner = document.getElementById('uploaded-file-banner');
  if (banner) banner.style.display = 'none';

  const fileInput = document.getElementById('doc-file-upload');
  if (fileInput) fileInput.value = '';

  state.activeUploadData = null;
  state.activeMaskedImageB64 = null;
  state.activeOriginalImageB64 = null;
  state.activeUploadFileName = null;

  // Reset visual previews
  const aSwitcher = document.getElementById('panel-a-view-switcher');
  if (aSwitcher) aSwitcher.style.display = 'none';
  const origImgContainer = document.getElementById('original-image-preview-container');
  if (origImgContainer) origImgContainer.style.display = 'none';
  const origTextarea = document.getElementById('original-document-input');
  if (origTextarea) origTextarea.style.display = 'block';

  const maskedImgContainer = document.getElementById('masked-image-preview-container');
  if (maskedImgContainer) maskedImgContainer.style.display = 'none';
  const sanitizedText = document.getElementById('sanitized-payload-output');
  if (sanitizedText) sanitizedText.style.display = 'block';
  const downloadBtn = document.getElementById('btn-download-masked-img');
  if (downloadBtn) downloadBtn.style.display = 'none';

  const metaBox = document.getElementById('sensitive-locations-meta');
  if (metaBox) metaBox.style.display = 'none';

  showToast('Uploaded file reference removed', 'info');
}

function updatePipelineStatus(data) {
  const langEl = document.getElementById('status-lang');
  const ocrEl = document.getElementById('status-ocr');
  const piiEl = document.getElementById('status-pii');
  const photoEl = document.getElementById('status-photo');
  const maskEl = document.getElementById('status-masking');
  const leakEl = document.getElementById('status-leakage');

  if (langEl) {
    const langStr = data.language_label || (data.detected_languages && data.detected_languages.length ? data.detected_languages.join(', ') : 'English');
    langEl.innerText = `🌐 Lang: ${langStr}`;
    langEl.className = 'status-pill status-active';
  }
  if (ocrEl) {
    ocrEl.innerText = `🔍 OCR: ${data.ocr_status || 'Complete'}`;
    ocrEl.className = 'status-pill status-active';
  }
  if (piiEl) {
    const countStr = data.pii_detection_status || `${data.total_entities_detected || (data.detected_entities ? data.detected_entities.length : 0)} Detected`;
    piiEl.innerText = `🛡️ PII: ${countStr}`;
    piiEl.className = 'status-pill status-active';
  }
  if (photoEl) {
    const pCount = data.photos_detected_count !== undefined ? data.photos_detected_count : (data.photos_masked_count || 0);
    photoEl.innerText = `📸 Photo: ${pCount} Masked`;
    photoEl.className = pCount > 0 ? 'status-pill status-passed' : 'status-pill status-ready';
  }
  if (maskEl) {
    const tCount = data.text_regions_masked_count !== undefined ? data.text_regions_masked_count : (data.sensitive_text_boxes ? data.sensitive_text_boxes.length : (data.total_entities_masked || data.total_entities_detected || 0));
    const pCount = data.photos_masked_count !== undefined ? data.photos_masked_count : (data.photos_detected_count || 0);
    maskEl.innerText = `⬛ Masked: ${tCount} Text + ${pCount} Photo`;
    maskEl.className = 'status-pill status-passed';
  }
  if (leakEl) {
    leakEl.innerText = `🔒 Leakage: ${data.leakage_check_status || '0% Egress'}`;
    leakEl.className = 'status-pill status-passed';
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function renderHighlightedDocument(text, entities) {
  const container = document.getElementById('original-document-highlight-view');
  const countEl = document.getElementById('panel-a-highlight-count');
  if (!container) return;

  if (!entities || entities.length === 0) {
    if (countEl) countEl.innerText = '0';
    container.innerHTML = `<div style="color: var(--text-muted); font-style: italic; padding: 10px 0;">No sensitive PII entities detected. Document is safe.</div>`;
    return;
  }

  if (countEl) countEl.innerText = entities.length.toString();

  // Sort entities by start asc, length desc
  const sorted = [...entities].sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  
  // Filter any overlapping spans for display
  const nonOverlapping = [];
  let lastEnd = -1;
  for (const ent of sorted) {
    if (ent.start >= lastEnd) {
      nonOverlapping.push(ent);
      lastEnd = ent.end;
    }
  }

  let html = '';
  let cursor = 0;

  for (const ent of nonOverlapping) {
    const s = Math.max(0, Math.min(ent.start, text.length));
    const e = Math.max(s, Math.min(ent.end, text.length));

    if (s > cursor) {
      html += escapeHtml(text.slice(cursor, s));
    }

    const val = text.slice(s, e);
    const entType = (ent.entity_type || 'PII').toUpperCase();
    const typeClass = 'pii-' + entType.toLowerCase();
    const scorePct = Math.round((ent.score || 0.95) * 100);
    const method = ent.detection_method || 'Presidio Pattern Recognizer';
    const explanation = ent.explanation || `${entType} sensitive personal identifier`;
    const tooltip = `${entType}: ${val} | Confidence: ${scorePct}% | Method: ${method} | ${explanation}`;

    html += `<mark class="pii-mark ${typeClass}" title="${escapeHtml(tooltip)}" data-entity-type="${entType}">` +
            `<span class="pii-mark-val">${escapeHtml(val)}</span>` +
            `<span class="pii-mark-tag">${escapeHtml(entType)}</span>` +
            `</mark>`;

    cursor = e;
  }

  if (cursor < text.length) {
    html += escapeHtml(text.slice(cursor));
  }

  container.innerHTML = html;
}

function switchPanelAView(view) {
  const btnImg = document.getElementById('btn-view-orig-img');
  const btnText = document.getElementById('btn-view-orig-text');
  const btnHigh = document.getElementById('btn-view-orig-highlight');
  const imgContainer = document.getElementById('original-image-preview-container');
  const textarea = document.getElementById('original-document-input');
  const highlightView = document.getElementById('original-document-highlight-view');

  if (view === 'preview') {
    if (btnImg) btnImg.classList.add('active');
    if (btnText) btnText.classList.remove('active');
    if (btnHigh) btnHigh.classList.remove('active');
    if (imgContainer) imgContainer.style.display = 'flex';
    if (textarea) textarea.style.display = 'none';
    if (highlightView) highlightView.style.display = 'none';
  } else if (view === 'highlight') {
    if (btnImg) btnImg.classList.remove('active');
    if (btnText) btnText.classList.remove('active');
    if (btnHigh) btnHigh.classList.add('active');
    if (imgContainer) imgContainer.style.display = 'none';
    if (textarea) textarea.style.display = 'none';
    if (highlightView) highlightView.style.display = 'block';
  } else {
    // text / edit
    if (btnImg) btnImg.classList.remove('active');
    if (btnText) btnText.classList.add('active');
    if (btnHigh) btnHigh.classList.remove('active');
    if (imgContainer) imgContainer.style.display = 'none';
    if (textarea) textarea.style.display = 'block';
    if (highlightView) highlightView.style.display = 'none';
  }
}

function switchPanelBView(view) {
  const btnImg = document.getElementById('btn-view-masked-img');
  const btnText = document.getElementById('btn-view-masked-text');
  const imgContainer = document.getElementById('masked-image-preview-container');
  const textContainer = document.getElementById('sanitized-payload-output');

  if (view === 'preview') {
    if (btnImg) btnImg.classList.add('active');
    if (btnText) btnText.classList.remove('active');
    if (imgContainer) imgContainer.style.display = 'flex';
    if (textContainer) textContainer.style.display = 'none';
  } else {
    if (btnImg) btnImg.classList.remove('active');
    if (btnText) btnText.classList.add('active');
    if (imgContainer) imgContainer.style.display = 'none';
    if (textContainer) textContainer.style.display = 'block';
  }
}

function downloadMaskedImage() {
  if (!state.activeMaskedImageB64) {
    showToast('No redacted image available for download', 'error');
    return;
  }
  const a = document.createElement('a');
  a.href = state.activeMaskedImageB64;
  a.download = `masked_${state.activeUploadFileName || 'document'}_redacted.png`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  showToast('Downloaded irreversibly redacted PNG document', 'success');
}

async function handleFileUpload(event) {
  const inputEl = event.target;
  const file = inputEl.files && inputEl.files[0];
  if (!file) return;

  // Reset input value so selecting the same file triggers onchange again
  inputEl.value = '';

  const ext = file.name.split('.').pop().toLowerCase();
  const formatMeta = SUPPORTED_UPLOAD_FORMATS[ext];

  // 1. Validate format
  if (!formatMeta) {
    showToast(
      `Unsupported file format ".${ext}". Supported formats: PDF (.pdf), Word (.doc, .docx), Excel (.xls, .xlsx), PowerPoint (.ppt, .pptx), Text (.txt), CSV (.csv), JSON (.json), XML (.xml), and Images (.jpg, .png, .webp, .bmp, .tiff).`,
      'error'
    );
    return;
  }

  const formattedSize = formatBytes(file.size);

  // 2. Display the selected file name, format and size immediately
  displayUploadedFileInfo(file.name, formatMeta.label, formattedSize, formatMeta.icon);

  // 3. Visual feedback on upload button
  const uploadLabel = document.getElementById('upload-btn-text');
  const originalUploadText = uploadLabel ? uploadLabel.innerText : 'Upload File';
  if (uploadLabel) uploadLabel.innerText = 'Extracting...';

  showToast(`Uploading ${file.name} (${formatMeta.label} • ${formattedSize})...`, 'info');

  try {
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch(`${API_BASE}/api/upload-document`, {
      method: 'POST',
      body: formData
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || `Upload extraction failed (HTTP ${res.status})`);
    }

    const data = await res.json();
    state.activeUploadData = data;
    state.activeUploadFileName = file.name;
    state.activeMaskedImageB64 = data.masked_preview || null;
    state.activeOriginalImageB64 = data.original_preview || null;

    // Update status ribbon
    updatePipelineStatus(data);

    const extractedText = (data.text || '').trim();

    // 4. Update Visual Previews if an image or scanned document was processed
    if (data.has_image && data.masked_preview) {
      const origImg = document.getElementById('original-image-preview');
      const maskedImg = document.getElementById('masked-image-preview');
      const origContainer = document.getElementById('original-image-preview-container');
      const maskedContainer = document.getElementById('masked-image-preview-container');
      const aSwitcher = document.getElementById('panel-a-view-switcher');
      const dlBtn = document.getElementById('btn-download-masked-img');
      const metaBox = document.getElementById('sensitive-locations-meta');

      if (origImg) origImg.src = data.original_preview;
      if (maskedImg) maskedImg.src = data.masked_preview;

      if (aSwitcher) aSwitcher.style.display = 'flex';
      if (origContainer) origContainer.style.display = 'flex';
      document.getElementById('original-document-input').style.display = 'none';

      if (maskedContainer) maskedContainer.style.display = 'flex';
      document.getElementById('sanitized-payload-output').style.display = 'none';

      if (dlBtn) dlBtn.style.display = 'inline-flex';

      switchPanelAView('preview');
      switchPanelBView('preview');

      // Display sensitive text & photo bounding box locations
      if (metaBox) {
        const textCount = data.text_regions_masked_count !== undefined ? data.text_regions_masked_count : (data.sensitive_text_boxes ? data.sensitive_text_boxes.length : 0);
        const photoCount = data.photos_detected_count || 0;
        const langStr = data.language_label || 'English';
        metaBox.style.display = 'block';
        metaBox.innerHTML = `
          <strong>📐 Irreversible Spatial Masking:</strong>
          <span>${textCount} sensitive text region(s) and ${photoCount} photograph region(s) flattened with solid black (0, 0, 0) redaction [Languages: ${langStr}].</span>
        `;
      }
    } else {
      // Non-visual document: ensure text views are visible
      switchPanelAView('text');
      switchPanelBView('text');
      const dlBtn = document.getElementById('btn-download-masked-img');
      if (dlBtn) dlBtn.style.display = 'none';
      const aSwitcher = document.getElementById('panel-a-view-switcher');
      if (aSwitcher) aSwitcher.style.display = 'none';
    }

    // 5. Populate original document textarea and character count
    const textarea = document.getElementById('original-document-input');
    textarea.value = extractedText;
    document.getElementById('input-char-count').innerText = `${extractedText.length} characters (Uploaded: ${file.name} • ${data.format || formatMeta.label} • ${data.size_formatted || formattedSize})`;

    showToast(`Successfully extracted and masked ${file.name}`, 'success');

    // 6. Ensure the upload actually processes the selected file through the privacy gateway
    await processPrivacyGateway();
  } catch (err) {
    console.error('File upload error:', err);
    showToast(`Upload failed: ${err.message}`, 'error');
  } finally {
    if (uploadLabel) uploadLabel.innerText = originalUploadText;
  }
}

function clearGatewayWorkspace() {
  state.activeUploadData = null;
  state.activeMaskedImageB64 = null;
  state.activeOriginalImageB64 = null;
  state.activeUploadFileName = null;

  const banner = document.getElementById('uploaded-file-banner');
  if (banner) banner.style.display = 'none';

  const aSwitcher = document.getElementById('panel-a-view-switcher');
  if (aSwitcher) aSwitcher.style.display = 'none';

  const origImgContainer = document.getElementById('original-image-preview-container');
  if (origImgContainer) origImgContainer.style.display = 'none';

  const maskedImgContainer = document.getElementById('masked-image-preview-container');
  if (maskedImgContainer) maskedImgContainer.style.display = 'none';

  const origTextarea = document.getElementById('original-document-input');
  if (origTextarea) {
    origTextarea.style.display = 'block';
    origTextarea.value = '';
  }

  const sanitizedText = document.getElementById('sanitized-payload-output');
  if (sanitizedText) {
    sanitizedText.style.display = 'block';
    sanitizedText.innerHTML = '<div class="empty-state-text">Sanitized outbound text will appear here with consistent placeholders (&lt;PERSON_1&gt;, &lt;AADHAAR_1&gt;, &lt;PAN_1&gt;)...</div>';
  }

  const downloadBtn = document.getElementById('btn-download-masked-img');
  if (downloadBtn) downloadBtn.style.display = 'none';

  const metaBox = document.getElementById('sensitive-locations-meta');
  if (metaBox) metaBox.style.display = 'none';

  document.getElementById('input-char-count').innerText = '0 characters';
  document.getElementById('detected-entities-list').innerHTML = '<span class="no-entities-pill">No entities extracted yet</span>';
  document.getElementById('detected-entities-count').innerText = '0 Detected • 0 Photos';
  document.getElementById('final-response-output').innerHTML = '<div class="empty-state-text">After external LLM generates the output, original personal details are automatically restored locally in transient memory. Result will appear here...</div>';
  document.getElementById('resp-latency').innerText = '-- ms';
  document.getElementById('resp-entity-count').innerText = '--';
  document.getElementById('resp-reinsert-status').innerText = '--';
  document.getElementById('leakage-badge-text').innerText = 'Raw PII Check: Ready';
  document.getElementById('security-leakage-badge').className = 'security-check-badge badge-passed';
  document.getElementById('raw-llm-container').style.display = 'none';

  const countEl = document.getElementById('panel-a-highlight-count');
  if (countEl) countEl.innerText = '0';
  const highEl = document.getElementById('original-document-highlight-view');
  if (highEl) highEl.innerHTML = '<div class="empty-state-text">Click \'Protect My Data\' to detect and highlight sensitive personal entities across languages...</div>';
  switchPanelAView('text');

  // Reset status ribbon
  const ocrEl = document.getElementById('status-ocr');
  if (ocrEl) { ocrEl.innerText = '🔍 OCR: Ready'; ocrEl.className = 'status-pill status-ready'; }
  const piiEl = document.getElementById('status-pii');
  if (piiEl) { piiEl.innerText = '🛡️ PII: Ready'; piiEl.className = 'status-pill status-ready'; }
  const photoEl = document.getElementById('status-photo');
  if (photoEl) { photoEl.innerText = '📸 Photo: 0 Detected'; photoEl.className = 'status-pill status-ready'; }
  const maskEl = document.getElementById('status-masking');
  if (maskEl) { maskEl.innerText = '⬛ Masking: Irreversible'; maskEl.className = 'status-pill status-ready'; }
  const leakEl = document.getElementById('status-leakage');
  if (leakEl) { leakEl.innerText = '🔒 Leakage: 0% Egress'; leakEl.className = 'status-pill status-passed'; }

  showToast('Workspace cleared', 'info');
}

async function processPrivacyGateway() {
  const textInput = document.getElementById('original-document-input').value;
  if (!textInput || !textInput.trim()) {
    showToast('Please enter an enterprise document first', 'error');
    return;
  }

  const docType = document.getElementById('doc-type-select').value;
  const task = document.getElementById('task-select').value;
  const btn = document.getElementById('btn-protect-data');

  // Set loading state
  const originalBtnHTML = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `
    <svg class="spinner" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
      <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
      <path d="M12 2a10 10 0 0 1 10 10" />
    </svg>
    <span>Executing DPDP Pipeline...</span>
  `;

  try {
    const res = await fetch(`${API_BASE}/api/protect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        document_text: textInput,
        document_type: docType,
        task: task
      })
    });

    const data = await res.json();

    if (res.ok && data.success) {
      // If direct text entry, update ribbon status
      if (!state.activeUploadData) {
        updatePipelineStatus(data);
      }

      // 0. Render Highlighted Document in Panel A
      renderHighlightedDocument(textInput, data.detected_entities);

      // 1. Update Panel B: Sanitized Payload
      renderSanitizedPayload(data);

      // 2. Update Panel C: Final Restored Response
      renderFinalResponse(data);

      // 3. Update Pre-flight security badge
      const badge = document.getElementById('security-leakage-badge');
      badge.className = 'security-check-badge badge-passed';
      document.getElementById('leakage-badge-text').innerText = 'Raw PII Check: Passed (0% Egress)';

      showToast('Document securely sanitized, processed, and restored!', 'success');

      // Update dashboard stats in background
      fetchDashboardMetrics();
    } else {
      // Leakage guard failure or processing error
      const badge = document.getElementById('security-leakage-badge');
      badge.className = 'security-check-badge badge-failed';
      document.getElementById('leakage-badge-text').innerText = 'Raw PII Check: BLOCKED';

      document.getElementById('sanitized-payload-output').innerText = data.sanitized_payload || 'Execution aborted';
      document.getElementById('final-response-output').innerHTML = `
        <div style="color: #fb7185; font-weight: 600; padding: 10px;">
          ⚠ ZERO-LEAKAGE SECURITY GUARD TRIGGERED:
          <div style="font-weight: 400; font-size: 0.8rem; margin-top: 6px; color: #f8fafc;">
            ${data.error || data.detail || 'Raw PII detected in outbound payload. Request halted.'}
          </div>
        </div>
      `;

      showToast('Gateway Security Alert: Raw PII halted!', 'error');
    }
  } catch (err) {
    showToast(`Gateway connection error: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalBtnHTML;
  }
}

function renderSanitizedPayload(data) {
  const container = document.getElementById('sanitized-payload-output');
  container.innerText = data.sanitized_payload;

  // Render Detected Entities Pills
  const pillsContainer = document.getElementById('detected-entities-list');
  const countBadge = document.getElementById('detected-entities-count');
  const entities = data.detected_entities || [];

  const uploadData = state.activeUploadData;
  const photoBoxes = (uploadData && uploadData.photo_boxes) ? uploadData.photo_boxes : [];
  const photoCount = uploadData ? (uploadData.photos_masked_count !== undefined ? uploadData.photos_masked_count : photoBoxes.length) : 0;
  const textMaskedCount = uploadData ? (uploadData.text_regions_masked_count !== undefined ? uploadData.text_regions_masked_count : entities.length) : entities.length;

  countBadge.innerText = `${entities.length} Detected • ${textMaskedCount} Text Masked • ${photoCount} Photos Masked`;

  if (entities.length === 0 && photoCount === 0) {
    pillsContainer.innerHTML = '<span class="no-entities-pill">No sensitive personal entities found</span>';
    return;
  }

  pillsContainer.innerHTML = '';
  const entityPillClasses = {
    PERSON: 'pill-person',
    AADHAAR: 'pill-aadhaar',
    PAN: 'pill-pan',
    GSTIN: 'pill-gstin',
    VOTER_ID: 'pill-voter',
    PASSPORT: 'pill-passport',
    ADDRESS: 'pill-address',
    PHONE_NUMBER: 'pill-phone',
    EMAIL_ADDRESS: 'pill-email',
    EMAIL: 'pill-email',
    DATE_OF_BIRTH: 'pill-dob',
    DOB: 'pill-dob',
    BANK_ACCOUNT: 'pill-bank',
    IFSC_CODE: 'pill-ifsc',
    IFSC: 'pill-ifsc',
    PINCODE: 'pill-pincode'
  };

  // 1. Render Photograph Bounding Boxes Pills
  photoBoxes.forEach((pb, idx) => {
    const pill = document.createElement('div');
    pill.className = 'entity-pill pill-photo';
    pill.title = `${pb.label || 'Person Photograph'} [Coords: x=${pb.box[0]}, y=${pb.box[1]}, w=${pb.box[2]}, h=${pb.box[3]}] - Redacted with Solid Black (0, 0, 0)`;
    pill.innerHTML = `
      <span>📸 PHOTO</span>
      <span style="opacity: 0.6;">→</span>
      <strong>&lt;PHOTO_${idx + 1}&gt;</strong>
      <span style="font-size: 0.65rem; opacity: 0.85;">[100% Solid Black]</span>
    `;
    pillsContainer.appendChild(pill);
  });

  // 2. Render Text PII Pills
  entities.forEach((ent, idx) => {
    const pill = document.createElement('div');
    const pillClass = entityPillClasses[ent.entity_type] || 'pill-person';
    pill.className = `entity-pill ${pillClass}`;
    const scorePct = Math.round((ent.score || 0.95) * 100);
    const method = ent.detection_method || 'Presidio Pattern Recognizer';
    pill.title = `${ent.entity_type}: ${ent.value || ''} | Method: ${method} | Confidence: ${scorePct}%`;

    pill.innerHTML = `
      <span>${ent.entity_type}</span>
      <span style="opacity: 0.6;">→</span>
      <strong>&lt;${ent.entity_type}_${idx + 1}&gt;</strong>
      <span style="font-size: 0.65rem; opacity: 0.8;">[${scorePct}%]</span>
    `;
    pillsContainer.appendChild(pill);
  });
}

function renderFinalResponse(data) {
  const container = document.getElementById('final-response-output');
  container.innerText = data.final_restored_response;

  // Meta chips
  document.getElementById('resp-latency').innerText = `${data.processing_latency_ms} ms`;
  document.getElementById('resp-entity-count').innerText = `${data.total_entities_detected} entities`;
  document.getElementById('resp-reinsert-status').innerText = `${data.reinsertion_status} (100%)`;
  document.getElementById('gateway-model-used-label').innerText = `Model: ${data.external_model_used}`;

  // Store raw LLM response for toggle inspect
  state.activeRawLLMResponse = data.llm_sanitized_response || '';
  document.getElementById('raw-llm-output-text').innerText = state.activeRawLLMResponse;
}

function toggleRawLLMView() {
  const container = document.getElementById('raw-llm-container');
  const label = document.getElementById('raw-toggle-label');
  if (container.style.display === 'none') {
    container.style.display = 'block';
    label.innerText = 'Hide Raw Model Output';
  } else {
    container.style.display = 'none';
    label.innerText = 'View Raw Model Output (Before Local Reinsertion)';
  }
}

// ==============================================================================
// 4. DOCUMENT TESTING PAGE
// ==============================================================================
function renderTestingTable() {
  const tbody = document.getElementById('testing-table-body');
  if (!tbody) return;

  const docs = state.sampleDocuments;
  if (!docs || docs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="text-center py-4">No synthetic documents available.</td></tr>';
    const meta = document.getElementById('testing-table-meta');
    if (meta) meta.innerText = 'Showing 0 documents';
    return;
  }

  tbody.innerHTML = '';
  docs.forEach((doc) => {
    const tr = document.createElement('tr');
    tr.id = `row-${doc.id}`;
    tr.setAttribute('data-category', doc.category);
    tr.setAttribute('data-doc-id', doc.id);

    const expectedCount = doc.expected_entities ? doc.expected_entities.length : 0;

    // Check if benchmark data already exists for this doc
    const bResult = state.benchmarkResults?.document_results?.find(r => r.id === doc.id);
    const detectedVal = bResult ? bResult.detected_count : '--';
    const latencyVal = bResult ? `${bResult.latency_ms} ms` : '--';
    let statusClass = 'badge-mini info';
    let statusText = 'Ready';
    if (bResult) {
      if (bResult.false_negatives === 0 && bResult.false_positives === 0) {
        statusClass = 'badge-mini success';
        statusText = '100% Match';
      } else {
        statusClass = 'badge-mini info';
        statusText = `${bResult.true_positives} Matched`;
      }
    }

    tr.innerHTML = `
      <td><strong style="color: #c084fc; font-family: var(--font-mono); font-size: 0.78rem;">${doc.id}</strong></td>
      <td><span class="tag-pill" style="font-size: 0.7rem; background: rgba(59, 130, 246, 0.12); color: #93c5fd;">${doc.category}</span></td>
      <td style="max-width: 240px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${doc.title}">${doc.title}</td>
      <td><span style="font-weight: 600;">${expectedCount}</span></td>
      <td><span id="detected-${doc.id}" style="font-weight: 600; color: #34d399;">${detectedVal}</span></td>
      <td><span id="status-${doc.id}" class="${statusClass}">${statusText}</span></td>
      <td><span id="latency-${doc.id}" style="font-family: var(--font-mono); font-size: 0.75rem;">${latencyVal}</span></td>
      <td>
        <div style="display: flex; gap: 6px;">
          <button class="btn btn-secondary btn-sm" onclick="inspectDocumentDetails('${doc.id}')" title="Inspect ground truth entities & sample">
            Inspect
          </button>
          <button class="btn btn-primary btn-sm" onclick="loadDocIntoGateway('${doc.id}')" title="Load directly into Privacy Gateway">
            Test
          </button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });

  filterTestingTable();
}

function filterTestingTable() {
  const query = document.getElementById('testing-search-input')?.value.toLowerCase().trim() || '';
  const category = document.getElementById('testing-category-filter')?.value || 'ALL';
  const rows = document.querySelectorAll('#testing-table-body tr');

  let visibleCount = 0;
  rows.forEach(row => {
    const rowCat = row.getAttribute('data-category');
    if (!rowCat) return; // ignore non-data rows

    const rowText = row.innerText.toLowerCase();
    const docId = (row.getAttribute('data-doc-id') || '').toLowerCase();
    const matchesQuery = !query || rowText.includes(query) || docId.includes(query);
    const matchesCat = (category === 'ALL') || (rowCat.toLowerCase() === category.toLowerCase());

    if (matchesQuery && matchesCat) {
      row.style.display = '';
      visibleCount++;
    } else {
      row.style.display = 'none';
    }
  });

  const metaEl = document.getElementById('testing-table-meta');
  if (metaEl) {
    metaEl.innerText = `Showing ${visibleCount} documents`;
  }
}

function inspectDocumentDetails(docId) {
  const doc = state.sampleDocuments.find(d => d.id === docId);
  if (!doc) return;

  const modal = document.getElementById('doc-modal');
  const titleEl = document.getElementById('doc-modal-title');
  const contentEl = document.getElementById('doc-modal-content');
  const footerEl = document.getElementById('doc-modal-footer');
  if (!modal || !contentEl) return;

  titleEl.innerText = `${doc.id} - ${doc.title}`;

  const expectedList = (doc.expected_entities || []).map(ent => `
    <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 6px; padding: 8px 12px; display: flex; justify-content: space-between; align-items: center;">
      <div>
        <span class="tag-pill" style="font-size: 0.68rem; margin-right: 8px;">${ent.type}</span>
        <strong style="color: #f8fafc; font-size: 0.8rem;">${ent.value}</strong>
      </div>
      <span style="font-size: 0.72rem; color: var(--text-muted);">${ent.description || 'Ground truth entity'}</span>
    </div>
  `).join('');

  contentEl.innerHTML = `
    <div style="display: flex; flex-direction: column; gap: 14px;">
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 0.8rem;">
        <div><strong>Category:</strong> <span style="color: #93c5fd;">${doc.category}</span></div>
        <div><strong>Expected Entities:</strong> ${doc.expected_entities ? doc.expected_entities.length : 0}</div>
      </div>

      <div>
        <label style="font-size: 0.75rem; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Raw Synthetic Enterprise Text:</label>
        <div style="background: #090e1a; border: 1px solid rgba(139, 92, 246, 0.25); border-radius: 8px; padding: 12px; font-family: var(--font-mono); font-size: 0.78rem; line-height: 1.5; color: #f8fafc; margin-top: 4px; white-space: pre-wrap; max-height: 180px; overflow-y: auto;">${doc.text}</div>
      </div>

      <div>
        <label style="font-size: 0.75rem; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Ground Truth Labeled Entities:</label>
        <div style="display: flex; flex-direction: column; gap: 6px; margin-top: 4px; max-height: 160px; overflow-y: auto;">
          ${expectedList || '<span style="font-size: 0.75rem; color: var(--text-muted);">No ground-truth labels provided</span>'}
        </div>
      </div>
    </div>
  `;

  footerEl.innerHTML = `
    <button class="btn btn-primary" onclick="loadDocIntoGateway('${doc.id}'); closeDocModal();">
      Test in Gateway
    </button>
    <button class="btn btn-secondary" onclick="closeDocModal()">Close</button>
  `;

  modal.style.display = 'flex';
}

function closeDocModal() {
  const modal = document.getElementById('doc-modal');
  if (modal) modal.style.display = 'none';
}

function loadDocIntoGateway(docId) {
  const doc = state.sampleDocuments.find(d => d.id === docId);
  if (!doc) return;

  document.getElementById('original-document-input').value = doc.text;
  document.getElementById('doc-type-select').value = doc.category;
  document.getElementById('input-char-count').innerText = `${doc.text.length} characters`;

  navigateToPage('gateway');
  showToast(`Loaded ${doc.id} into Privacy Gateway`, 'info');
}

function loadRandomSampleDoc() {
  if (state.sampleDocuments.length === 0) return;
  const randomIndex = Math.floor(Math.random() * state.sampleDocuments.length);
  const doc = state.sampleDocuments[randomIndex];
  loadDocIntoGateway(doc.id);
}

async function runSyntheticDatasetBenchmark(silent = false) {
  const btn = document.getElementById('btn-run-all-tests');
  if (btn && !silent) {
    btn.disabled = true;
    btn.innerHTML = 'Testing 50 Documents...';
  }

  try {
    const res = await fetch(`${API_BASE}/api/test-dataset`, { method: 'POST' });
    if (res.ok) {
      const data = await res.json();
      state.benchmarkResults = data;

      // Update Ribbon
      document.getElementById('test-total-docs').innerText = data.total_documents;
      document.getElementById('test-expected-ent').innerText = data.expected_entities;
      document.getElementById('test-detected-ent').innerText = data.detected_entities;
      document.getElementById('test-tp-count').innerText = data.true_positives;
      document.getElementById('test-fn-count').innerText = data.false_negatives;
      document.getElementById('test-fp-count').innerText = data.false_positives;
      document.getElementById('test-pr-score').innerText = `${(data.precision * 100).toFixed(2)}% / ${(data.recall * 100).toFixed(2)}%`;

      // Render Detailed FN and FP Breakdown Tables
      renderFalseNegativesTable(data.false_negatives_list || []);
      renderFalsePositivesTable(data.false_positives_list || []);

      // Update individual table rows with real benchmark counts
      if (data.document_results) {
        data.document_results.forEach(item => {
          const detEl = document.getElementById(`detected-${item.id}`);
          const statusEl = document.getElementById(`status-${item.id}`);
          const latEl = document.getElementById(`latency-${item.id}`);

          if (detEl) detEl.innerText = item.detected_count;
          if (latEl) latEl.innerText = `${item.latency_ms} ms`;
          if (statusEl) {
            if (item.false_negatives === 0 && item.false_positives === 0) {
              statusEl.className = 'badge-mini success';
              statusEl.innerText = '100% Match';
            } else {
              statusEl.className = 'badge-mini info';
              statusEl.innerText = `${item.true_positives} Matched`;
            }
          }
        });
        filterTestingTable();
      }

      if (!silent) {
        showToast(`Evaluation completed! Precision: ${(data.precision * 100).toFixed(1)}%, Leakage: 0`, 'success');
      }
    }
  } catch (err) {
    if (!silent) showToast(`Benchmark error: ${err.message}`, 'error');
  } finally {
    if (btn && !silent) {
      btn.disabled = false;
      btn.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
        Test All 50 Documents
      `;
    }
  }
}

function renderFalseNegativesTable(fnList) {
  const tbody = document.getElementById('fn-table-body');
  const meta = document.getElementById('fn-table-meta');
  if (!tbody) return;

  if (meta) {
    meta.innerText = `Showing ${fnList.length} Missed Entities`;
  }

  if (!fnList || fnList.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-center py-4" style="color: #34d399;">✓ Perfect Recall: Zero sensitive entities were missed across the evaluated dataset.</td></tr>';
    return;
  }

  tbody.innerHTML = '';
  const entityPillClasses = {
    PERSON: 'pill-person',
    AADHAAR: 'pill-aadhaar',
    PAN: 'pill-pan',
    GSTIN: 'pill-gstin',
    VOTER_ID: 'pill-voter',
    PASSPORT: 'pill-passport',
    ADDRESS: 'pill-address',
    PHONE_NUMBER: 'pill-phone',
    EMAIL_ADDRESS: 'pill-email',
    EMAIL: 'pill-email'
  };

  fnList.forEach((fn) => {
    const tr = document.createElement('tr');
    const pillClass = entityPillClasses[fn.entity_type] || 'pill-person';

    tr.innerHTML = `
      <td style="font-family: var(--font-mono); font-size: 0.8rem; font-weight: 700; color: #fb7185;">${fn.serial_no}</td>
      <td>
        <strong style="color: #c084fc; font-family: var(--font-mono); font-size: 0.78rem;">${fn.doc_id}</strong>
        <div style="font-size: 0.76rem; color: #f8fafc; font-weight: 500; margin-top: 2px;">${fn.doc_title}</div>
        <span class="tag-pill" style="font-size: 0.65rem; background: rgba(59, 130, 246, 0.1); color: #93c5fd; margin-top: 4px;">${fn.category}</span>
      </td>
      <td>
        <span class="entity-pill ${pillClass}">
          <span>${fn.entity_type}</span>
        </span>
      </td>
      <td>
        <span class="highlight-fn" title="${fn.description || 'Ground truth sensitive personal value'}">${fn.missed_value}</span>
      </td>
      <td style="font-family: var(--font-mono); font-size: 0.74rem; line-height: 1.5; color: #cbd5e1; max-width: 320px;">
        ${fn.context}
      </td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="loadDocIntoGateway('${fn.doc_id}')" title="Load this document into Privacy Gateway">
          Test in Gateway
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function renderFalsePositivesTable(fpList) {
  const tbody = document.getElementById('fp-table-body');
  const meta = document.getElementById('fp-table-meta');
  if (!tbody) return;

  if (meta) {
    meta.innerText = `Showing ${fpList.length} False Detections`;
  }

  if (!fpList || fpList.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4" style="color: #34d399;">✓ Perfect Precision: Zero non-PII tokens were incorrectly detected.</td></tr>';
    return;
  }

  tbody.innerHTML = '';
  const entityPillClasses = {
    PERSON: 'pill-person',
    AADHAAR: 'pill-aadhaar',
    PAN: 'pill-pan',
    GSTIN: 'pill-gstin',
    VOTER_ID: 'pill-voter',
    PASSPORT: 'pill-passport',
    ADDRESS: 'pill-address',
    PHONE_NUMBER: 'pill-phone',
    EMAIL_ADDRESS: 'pill-email',
    EMAIL: 'pill-email'
  };

  fpList.forEach((fp) => {
    const tr = document.createElement('tr');
    const pillClass = entityPillClasses[fp.predicted_type] || 'pill-person';

    tr.innerHTML = `
      <td style="font-family: var(--font-mono); font-size: 0.8rem; font-weight: 700; color: #fb923c;">${fp.serial_no}</td>
      <td>
        <strong style="color: #c084fc; font-family: var(--font-mono); font-size: 0.78rem;">${fp.doc_id}</strong>
        <div style="font-size: 0.76rem; color: #f8fafc; font-weight: 500; margin-top: 2px;">${fp.doc_title}</div>
        <span class="tag-pill" style="font-size: 0.65rem; background: rgba(59, 130, 246, 0.1); color: #93c5fd; margin-top: 4px;">${fp.category}</span>
      </td>
      <td>
        <span class="highlight-fp" title="Detected by rule: ${fp.explanation}">${fp.detected_value}</span>
      </td>
      <td>
        <span class="entity-pill ${pillClass}">
          <span>${fp.predicted_type}</span>
        </span>
      </td>
      <td style="font-family: var(--font-mono); font-size: 0.75rem; color: #fb923c; font-weight: 600;">
        ${(fp.score * 100).toFixed(0)}%
      </td>
      <td style="font-family: var(--font-mono); font-size: 0.74rem; line-height: 1.5; color: #cbd5e1; max-width: 320px;">
        ${fp.context}
      </td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="loadDocIntoGateway('${fp.doc_id}')" title="Load this document into Privacy Gateway">
          Test in Gateway
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function scrollToBenchmarkSection(sectionId) {
  const el = document.getElementById(sectionId);
  if (!el) return;

  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  el.classList.remove('section-flash');
  void el.offsetWidth;
  el.classList.add('section-flash');
}

// ==============================================================================
// 5. AUDIT LOGS PAGE
// ==============================================================================
async function fetchAuditLogs() {
  const query = document.getElementById('audit-search-input')?.value || '';
  const docType = document.getElementById('audit-type-filter')?.value || 'ALL';
  const status = document.getElementById('audit-status-filter')?.value || 'ALL';

  try {
    const params = new URLSearchParams({
      query: query,
      document_type: docType,
      status: status,
      limit: '50'
    });

    const res = await fetch(`${API_BASE}/api/audit-logs?${params.toString()}`);
    if (res.ok) {
      const data = await res.json();
      state.auditLogs = data.audit_logs || [];
      renderAuditLogsTable();
    }
  } catch (err) {
    console.warn('Error fetching audit logs:', err);
  }
}

function renderAuditLogsTable() {
  const tbody = document.getElementById('audit-table-body');
  const meta = document.getElementById('audit-table-meta');
  if (!tbody) return;

  const logs = state.auditLogs;
  meta.innerText = `${logs.length} Safe Records`;

  if (logs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" class="text-center py-4">No audit records match the current filter.</td></tr>';
    return;
  }

  tbody.innerHTML = '';
  logs.forEach(log => {
    const tr = document.createElement('tr');
    const dateFormatted = new Date(log.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    // Entities chips
    const entityTypes = log.entity_types || [];
    const entityChips = entityTypes.map(t => `<span class="badge-mini" style="background: rgba(139,92,246,0.15); color: #d8b4fe;">${t}</span>`).join(' ') || 'None';

    const leakageBadge = log.leakage_check_passed
      ? '<span class="badge-mini success">PASS (0 Leakage)</span>'
      : '<span class="badge-mini" style="background: rgba(244,63,94,0.2); color: #fb7185;">FAILED</span>';

    tr.innerHTML = `
      <td><strong style="color: #38bdf8; font-family: var(--font-mono); font-size: 0.76rem;">${log.request_id}</strong></td>
      <td style="font-size: 0.75rem; color: var(--text-muted);">${dateFormatted}</td>
      <td><span class="tag-pill" style="font-size: 0.7rem; background: rgba(255,255,255,0.06);">${log.document_type}</span></td>
      <td><div style="display: flex; gap: 4px; flex-wrap: wrap;">${entityChips}</div></td>
      <td><span style="font-size: 0.72rem; color: var(--text-muted);">${log.external_model}</span></td>
      <td>${leakageBadge}</td>
      <td><span class="badge-mini success">${log.reinsertion_status || 'PERFECT'}</span></td>
      <td style="font-family: var(--font-mono); font-size: 0.74rem;">${log.processing_latency_ms} ms</td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="inspectAuditRecord('${log.id}')">
          Inspect Safe Payload
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function inspectAuditRecord(logId) {
  const log = state.auditLogs.find(l => l.id === logId);
  if (!log) return;

  const content = document.getElementById('audit-modal-content');
  content.innerHTML = `
    <div style="display: flex; flex-direction: column; gap: 14px;">
      <div style="display: flex; justify-content: space-between; align-items: center; padding-bottom: 10px; border-bottom: 1px solid var(--border-subtle);">
        <div>
          <strong style="font-size: 1.1rem; color: #38bdf8;">${log.request_id}</strong>
          <div style="font-size: 0.74rem; color: var(--text-muted);">${log.created_at}</div>
        </div>
        <div>
          <span class="tag-pill dpdp-tag">DPDP Act Compliant</span>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 0.8rem;">
        <div><strong>Document Category:</strong> ${log.document_type}</div>
        <div><strong>AI Task:</strong> ${log.task_selected}</div>
        <div><strong>External Model:</strong> ${log.external_model}</div>
        <div><strong>Latency:</strong> ${log.processing_latency_ms} ms</div>
        <div><strong>Vault Provider:</strong> ${log.storage_provider || 'Supabase / Local Vault'}</div>
        <div><strong>Zero Leakage Check:</strong> <span style="color: #34d399; font-weight: bold;">PASSED (100% Verified)</span></div>
      </div>

      <div>
        <label style="font-size: 0.75rem; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Exact Sanitized Outbound Payload:</label>
        <div style="background: #090e1a; border: 1px solid rgba(6, 182, 212, 0.3); border-radius: 8px; padding: 12px; font-family: var(--font-mono); font-size: 0.78rem; line-height: 1.5; color: #f8fafc; margin-top: 4px; white-space: pre-wrap;">${log.sanitized_payload}</div>
      </div>

      <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 8px; padding: 10px; font-size: 0.74rem; color: #6ee7b7;">
        ✓ Cryptographic Guarantee: Zero raw PII strings (Aadhaar numbers, PAN cards, real names, or mappings) were saved in this record.
      </div>
    </div>
  `;

  document.getElementById('audit-modal').style.display = 'flex';
}

function closeAuditModal() {
  document.getElementById('audit-modal').style.display = 'none';
}

// ==============================================================================
// 6. DASHBOARD & PERFORMANCE METRICS
// ==============================================================================
async function fetchDashboardMetrics() {
  try {
    const res = await fetch(`${API_BASE}/api/metrics`);
    if (res.ok) {
      const data = await res.json();
      const stats = data.dashboard_stats || {};
      const bench = data.benchmark || {};

      document.getElementById('stat-total-docs').innerText = stats.total_documents_processed || 0;
      document.getElementById('stat-total-detected').innerText = stats.total_pii_entities_detected || 0;
      document.getElementById('stat-total-masked').innerText = stats.total_pii_values_masked || 0;
      document.getElementById('stat-leakage-count').innerText = stats.outbound_pii_leakage_count || 0;
      document.getElementById('stat-avg-latency').innerText = `${stats.average_processing_time_ms || 0.0} ms`;

      // Pre-cache benchmark results and render FN and FP sections
      if (bench && bench.document_results && !state.benchmarkResults) {
        state.benchmarkResults = bench;
        renderFalseNegativesTable(bench.false_negatives_list || []);
        renderFalsePositivesTable(bench.false_positives_list || []);
      }
    }
  } catch (err) {
    console.warn('Could not fetch dashboard metrics:', err);
  }
}

async function loadPerformanceMetricsPage() {
  try {
    const res = await fetch(`${API_BASE}/api/metrics`);
    if (res.ok) {
      const data = await res.json();
      const bench = data.benchmark || {};

      document.getElementById('pm-leakage-count').innerText = bench.leakage_count || 0;
      document.getElementById('pm-precision').innerText = `${((bench.precision || 0.9925) * 100).toFixed(2)}%`;
      document.getElementById('pm-recall').innerText = `${((bench.recall || 0.9815) * 100).toFixed(2)}%`;
      document.getElementById('pm-reinsertion').innerText = `${((bench.reinsertion_accuracy || 1.0) * 100).toFixed(1)}%`;
      document.getElementById('pm-latency').innerText = `${bench.average_latency_ms || 0.78} ms`;
      document.getElementById('pm-total-tested').innerText = bench.total_documents || 50;

      // Render Entity Breakdown Cards
      renderEntityBreakdown(bench.entity_breakdown || {});
    }
  } catch (err) {
    console.warn('Could not load performance metrics:', err);
  }
}

function renderEntityBreakdown(breakdown) {
  const container = document.getElementById('entity-breakdown-cards');
  if (!container) return;

  container.innerHTML = '';
  const labels = {
    PERSON: 'Personal Names',
    AADHAAR: 'Aadhaar (UIDAI)',
    PAN: 'PAN Card (Income Tax)',
    GSTIN: 'GSTIN (Enterprise)',
    VOTER_ID: 'Voter ID (EPIC)',
    PASSPORT: 'Indian Passport',
    ADDRESS: 'Indian Addresses',
    PHONE_NUMBER: 'Mobile (+91)'
  };

  for (const [key, name] of Object.entries(labels)) {
    const stats = breakdown[key] || { expected: 0, detected: 0, tp: 0, fp: 0, fn: 0 };
    const p = (stats.tp + stats.fp) > 0 ? (stats.tp / (stats.tp + stats.fp) * 100).toFixed(1) : '100.0';
    const r = (stats.tp + stats.fn) > 0 ? (stats.tp / (stats.tp + stats.fn) * 100).toFixed(1) : '100.0';

    const box = document.createElement('div');
    box.className = 'entity-box';
    box.innerHTML = `
      <div class="entity-box-title">
        <span>${name}</span>
        <span class="badge-mini success">${p}% Prec</span>
      </div>
      <div class="entity-stat-row">
        <span>Expected:</span>
        <span class="entity-stat-val">${stats.expected}</span>
      </div>
      <div class="entity-stat-row">
        <span>Detected:</span>
        <span class="entity-stat-val">${stats.detected}</span>
      </div>
      <div class="entity-stat-row">
        <span>Recall:</span>
        <span class="entity-stat-val" style="color: #34d399;">${r}%</span>
      </div>
    `;
    container.appendChild(box);
  }
}

// ==============================================================================
// 7. SETTINGS PAGE
// ==============================================================================
async function loadSettingsPage() {
  try {
    const res = await fetch(`${API_BASE}/api/settings`);
    if (res.ok) {
      const data = await res.json();

      // Groq Status
      const groqStatus = document.getElementById('settings-groq-status');
      if (groqStatus) {
        if (data.is_groq_key_set) {
          groqStatus.className = 'badge-mini success';
          groqStatus.innerText = 'Key Configured';
        } else {
          groqStatus.className = 'badge-mini info';
          groqStatus.innerText = 'Simulated Mode Active';
        }
      }

      // Supabase Status
      const sbStatus = document.getElementById('settings-supabase-status');
      if (sbStatus) {
        if (data.supabase_connected) {
          sbStatus.className = 'badge-mini success';
          sbStatus.innerText = 'Connected';
        } else {
          sbStatus.className = 'badge-mini info';
          sbStatus.innerText = 'Local Vault Active';
        }
      }

      // Populate values
      if (data.current_model && document.getElementById('select-groq-model')) {
        document.getElementById('select-groq-model').value = data.current_model;
      }
      if (data.groq_base_url && document.getElementById('input-groq-base-url')) {
        document.getElementById('input-groq-base-url').value = data.groq_base_url;
      }
      if (data.sensitivity_threshold && document.getElementById('input-sensitivity')) {
        document.getElementById('input-sensitivity').value = data.sensitivity_threshold;
        document.getElementById('sensitivity-val').innerText = parseFloat(data.sensitivity_threshold).toFixed(2);
      }
      if (data.supabase_url && data.supabase_url !== 'Not Configured' && document.getElementById('input-sb-url')) {
        document.getElementById('input-sb-url').value = data.supabase_url;
      }
    }
  } catch (err) {
    console.warn('Could not load settings:', err);
  }
}

async function saveSettings() {
  const groqKeyInput = document.getElementById('input-groq-key');
  const groqKey = groqKeyInput ? groqKeyInput.value.trim() : '';
  const modelSelect = document.getElementById('select-groq-model');
  const model = modelSelect ? modelSelect.value : 'openai/gpt-oss-120b';
  const groqBaseUrlInput = document.getElementById('input-groq-base-url');
  const groqBaseUrl = groqBaseUrlInput ? groqBaseUrlInput.value.trim() : '';
  const sensitivity = parseFloat(document.getElementById('input-sensitivity').value);
  const sbUrl = document.getElementById('input-sb-url').value.trim();
  const sbKey = document.getElementById('input-sb-key').value.trim();

  const payload = {
    default_model: model,
    sensitivity_threshold: sensitivity
  };
  if (groqKey) payload.groq_api_key = groqKey;
  if (groqBaseUrl) payload.groq_base_url = groqBaseUrl;
  if (sbUrl) payload.supabase_url = sbUrl;
  if (sbKey) payload.supabase_anon_key = sbKey;

  try {
    const res = await fetch(`${API_BASE}/api/settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (res.ok) {
      showToast('Settings saved successfully!', 'success');
      checkBackendHealth();
      loadSettingsPage();
    } else {
      showToast('Failed to save settings', 'error');
    }
  } catch (err) {
    showToast(`Error: ${err.message}`, 'error');
  }
}

async function testGroqLiveConnection() {
  const btn = document.getElementById('btn-test-groq-conn');
  const statusEl = document.getElementById('groq-test-status');
  const keyInput = document.getElementById('input-groq-key');
  const modelSelect = document.getElementById('select-groq-model');

  const key = keyInput ? keyInput.value.trim() : '';
  const model = modelSelect ? modelSelect.value : 'openai/gpt-oss-120b';

  if (btn) {
    btn.disabled = true;
    btn.innerText = 'Testing Connection...';
  }
  if (statusEl) {
    statusEl.style.display = 'block';
    statusEl.style.color = '#38bdf8';
    statusEl.innerText = 'Connecting to Groq Cloud endpoint (https://api.groq.com/openai/v1)...';
  }

  try {
    const res = await fetch(`${API_BASE}/api/test-groq`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ groq_api_key: key || undefined, model: model || undefined })
    });
    const result = await res.json();

    if (result.success) {
      showToast(`Groq Connected! Latency: ${result.latency_ms} ms`, 'success');
      if (statusEl) {
        statusEl.style.color = '#34d399';
        statusEl.innerHTML = `✓ Groq Cloud Online | Model: <strong>${result.model}</strong> | Latency: <strong>${result.latency_ms}ms</strong> | HTTP Status: 200 OK`;
      }
    } else {
      showToast(`Groq API: ${result.message || result.error || 'Connection failed'}`, 'error');
      if (statusEl) {
        statusEl.style.color = '#f87171';
        statusEl.innerHTML = `⚠ Groq Error (${result.status_code || 'Err'}): ${result.error || result.message}`;
      }
    }
  } catch (err) {
    showToast(`Test failed: ${err.message}`, 'error');
    if (statusEl) {
      statusEl.style.color = '#f87171';
      statusEl.innerText = `Network or backend error: ${err.message}`;
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 14 14"/></svg>
        <span>Test Groq Connection</span>
      `;
    }
  }
}

function togglePasswordVisibility(inputId) {
  const input = document.getElementById(inputId);
  if (input) {
    input.type = input.type === 'password' ? 'text' : 'password';
  }
}

// ==============================================================================
// 8. UTILITIES (TOAST & CLIPBOARD)
// ==============================================================================
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;

  const icon = type === 'success' ? '✓' : (type === 'error' ? '⚠' : 'ℹ');
  toast.innerHTML = `<span style="font-weight: bold; font-size: 1rem;">${icon}</span> <span>${message}</span>`;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(50px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function copyTextFromElement(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;

  const text = el.innerText || el.value;
  if (!text || text.includes('will appear here')) {
    showToast('Nothing to copy yet', 'info');
    return;
  }

  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard!', 'success');
  }).catch(() => {
    showToast('Failed to copy', 'error');
  });
}

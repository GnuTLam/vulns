(() => {
  const root = document.documentElement;
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';

  // Form-encoded POST with the page's CSRF token, the shape the server's form handlers expect.
  const postForm = (url, fields) =>
    fetch(url, { method: 'POST', body: new URLSearchParams({ ...fields, csrf: csrfToken }) });

  // An expired session redirects to /login; never render that page inside a panel.
  const isSignInRedirect = (response) => response.redirected && new URL(response.url).pathname === '/login';

  const plainClick = (event) =>
    event.button === 0 && !event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey;

  // Select the tab and the pane whose data value is `name`.
  const showTab = (tabs, panes, name, tabKey, paneKey) => {
    tabs.forEach((tab) => {
      const selected = tab.dataset[tabKey] === name;
      tab.classList.toggle('active', selected);
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
    });
    panes.forEach((pane) => {
      const selected = pane.dataset[paneKey] === name;
      pane.classList.toggle('active', selected);
      pane.setAttribute('aria-hidden', String(!selected));
    });
  };

  // Highlight a drop zone while files are dragged over it; dropped files replace the input's selection.
  const bindDropZone = (zone, input, onChange, { single = false } = {}) => {
    if (!zone || !input) return;
    ['dragenter', 'dragover'].forEach((name) =>
      zone.addEventListener(name, (event) => {
        event.preventDefault();
        zone.classList.add('dragover');
      }),
    );
    ['dragleave', 'drop'].forEach((name) =>
      zone.addEventListener(name, (event) => {
        event.preventDefault();
        zone.classList.remove('dragover');
      }),
    );
    zone.addEventListener('drop', (event) => {
      const files = [...event.dataTransfer.files];
      if (!files.length) return;
      const transfer = new DataTransfer();
      (single ? files.slice(0, 1) : files).forEach((file) => transfer.items.add(file));
      input.files = transfer.files;
      onChange();
    });
  };

  // A selected file shown before upload: preview, name and a detail line.
  const fileRow = (preview, file, detail) => {
    const row = document.createElement('article');
    row.className = 'pending-file';
    const info = document.createElement('div');
    const name = document.createElement('strong');
    name.textContent = file.name;
    const note = document.createElement('small');
    note.textContent = detail;
    info.append(name, note);
    row.append(preview, info);
    return row;
  };
  const fileBadge = (text) => {
    const badge = document.createElement('div');
    badge.className = 'file-type';
    badge.textContent = text;
    return badge;
  };
  const kilobytes = (file) => `${(file.size / 1024).toFixed(1)} KB`;

  const savedTheme = localStorage.getItem('vulns-theme');
  if (savedTheme === 'light' || savedTheme === 'dark') root.dataset.theme = savedTheme;

  document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
    const label = button.querySelector('[data-theme-label]');
    const update = () => {
      if (label) label.textContent = root.dataset.theme === 'light' ? button.dataset.labelDark : button.dataset.labelLight;
    };
    update();
    button.addEventListener('click', () => {
      root.dataset.theme = root.dataset.theme === 'light' ? 'dark' : 'light';
      localStorage.setItem('vulns-theme', root.dataset.theme);
      update();
    });
  });

  const sidebar = document.querySelector('#sidebar');
  const explorer = document.querySelector('#program-explorer');
  const overlay = document.querySelector('.mobile-overlay');
  const sidebarToggles = [...document.querySelectorAll('[data-sidebar-toggle]')];
  const explorerToggles = [...document.querySelectorAll('[data-explorer-toggle]')];

  const syncDrawers = () => {
    const sidebarOpen = Boolean(sidebar?.classList.contains('open'));
    const explorerOpen = Boolean(explorer?.classList.contains('open'));
    overlay?.classList.toggle('visible', sidebarOpen || explorerOpen);
    document.body.classList.toggle('drawer-open', sidebarOpen || explorerOpen);
    sidebarToggles.forEach((control) => control.setAttribute('aria-expanded', String(sidebarOpen)));
    explorerToggles.forEach((control) => control.setAttribute('aria-expanded', String(explorerOpen)));
  };
  const closeDrawers = () => {
    sidebar?.classList.remove('open');
    explorer?.classList.remove('open');
    syncDrawers();
  };
  const openDrawer = (panel, other) => {
    other?.classList.remove('open');
    const opened = panel?.classList.toggle('open');
    syncDrawers();
    // Move focus into the opened panel so keyboard users are not stranded.
    if (opened) panel?.querySelector('a,button,input')?.focus();
  };
  sidebarToggles.forEach((control) => control.addEventListener('click', () => openDrawer(sidebar, explorer)));
  explorerToggles.forEach((control) => control.addEventListener('click', () => openDrawer(explorer, sidebar)));
  overlay?.addEventListener('click', closeDrawers);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && document.body.classList.contains('drawer-open')) closeDrawers();
  });
  // Drop the overlay when the viewport grows past the drawer breakpoint.
  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      const explorerIsDrawer = window.matchMedia('(max-width:1180px)').matches;
      const sidebarIsDrawer = window.matchMedia('(max-width:1000px)').matches;
      if (!sidebarIsDrawer) sidebar?.classList.remove('open');
      if (!explorerIsDrawer) explorer?.classList.remove('open');
      syncDrawers();
    }, 120);
  });
  syncDrawers();

  const explorerSearch = document.querySelector('[data-explorer-search]');
  explorerSearch?.addEventListener('input', () => {
    const term = explorerSearch.value.trim().toLocaleLowerCase();
    document.querySelectorAll('[data-program-node]').forEach((node) => {
      const programMatch = node.dataset.programName.includes(term);
      const findingMatch = [...node.querySelectorAll('[data-finding-name]')].some((item) =>
        item.dataset.findingName.includes(term),
      );
      node.hidden = Boolean(term) && !programMatch && !findingMatch;
      if (term && findingMatch) node.open = true;
    });
  });
  document.querySelectorAll('[data-program-node]').forEach((node) => {
    const key = `vulns-explorer:${node.dataset.programName}`;
    if (!node.classList.contains('selected') && localStorage.getItem(key) === 'open') node.open = true;
    node.addEventListener('toggle', () => localStorage.setItem(key, node.open ? 'open' : 'closed'));
  });

  // Record drawer: a plain click on a registry row opens it; modified clicks still navigate.
  const drawer = document.querySelector('#record-drawer');
  const drawerBody = document.querySelector('[data-drawer-body]');
  const drawerLoading = document.querySelector('[data-drawer-loading]');
  let panelReturnFocus = null;

  const closeRecordPanel = () => {
    if (!drawer || drawer.hidden) return;
    drawer.hidden = true;
    document.body.classList.remove('drawer-modal-open');
    drawerBody.replaceChildren();
    panelReturnFocus?.focus?.();
    panelReturnFocus = null;
  };
  drawer?.addEventListener('click', (event) => {
    if (event.target.closest('[data-drawer-close]')) closeRecordPanel();
  });

  const bindRecordPanel = () => {
    const moveSelect = drawerBody.querySelector('.move-form select');
    const moveButton = drawerBody.querySelector('.move-form button[type="submit"]');
    const syncMove = () => {
      if (moveButton) moveButton.disabled = !moveSelect?.value;
    };
    moveSelect?.addEventListener('change', syncMove);
    syncMove();

    const panes = [...drawerBody.querySelectorAll('[data-drawer-pane]')];
    const tabs = [...drawerBody.querySelectorAll('[data-drawer-tab]')];
    tabs.forEach((tab) =>
      tab.addEventListener('click', () => {
        const wanted = tab.dataset.drawerTab;
        showTab(tabs, panes, wanted, 'drawerTab', 'drawerPane');

        // The editor is the real edit page, loaded into a frame on first use.
        const pane = panes.find((item) => item.dataset.drawerPane === wanted);
        if (wanted === 'edit' && pane && !pane.querySelector('iframe')) {
          const frame = document.createElement('iframe');
          frame.className = 'drawer-frame';
          frame.src = pane.dataset.editUrl;
          frame.title = tab.textContent || 'editor';
          frame.addEventListener('load', () => {
            let path = '';
            try {
              path = frame.contentWindow.location.pathname;
            } catch {
              return; // same-origin here, but never throw out of a load handler
            }
            // A save redirects away from /edit: close the drawer so the list shows the new values.
            if (path && !path.endsWith('/edit')) {
              closeRecordPanel();
              window.location.reload();
            }
          });
          pane.append(frame);
        }
      }),
    );
  };

  const initReportReaders = (scope = document) => {
    scope.querySelectorAll('[data-report-reader]:not([data-reader-ready])').forEach((reader) => {
      reader.dataset.readerReady = 'true';
      const headings = [...reader.querySelectorAll('h1, h2, h3')].filter((heading) => heading.textContent.trim());
      if (headings.length >= 2) {
        const toc = document.createElement('nav');
        toc.className = 'report-toc';
        toc.setAttribute('aria-label', reader.dataset.tocLabel);
        const label = document.createElement('strong');
        label.textContent = reader.dataset.tocLabel;
        const links = document.createElement('div');
        links.className = 'report-toc-links';
        headings.forEach((heading) => {
          const link = document.createElement('button');
          link.type = 'button';
          link.className = `report-toc-link level-${heading.tagName.slice(1)}`;
          link.textContent = heading.textContent.trim();
          link.addEventListener('click', () => {
            const behavior = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';
            heading.scrollIntoView({ behavior, block: 'start' });
            heading.setAttribute('tabindex', '-1');
            heading.focus({ preventScroll: true });
          });
          links.append(link);
        });
        toc.append(label, links);
        reader.before(toc);
      }
      if (navigator.clipboard?.writeText) {
        reader.querySelectorAll('pre > code').forEach((code) => {
          const pre = code.parentElement;
          pre.classList.add('code-block');
          const button = document.createElement('button');
          button.type = 'button';
          button.className = 'code-copy';
          button.textContent = reader.dataset.copyLabel;
          button.setAttribute('aria-label', reader.dataset.copyLabel);
          button.setAttribute('aria-live', 'polite');
          button.addEventListener('click', async () => {
            try {
              await navigator.clipboard.writeText(code.textContent);
            } catch (_error) {
              return; // permission denied or unavailable: keep the stable Copy label
            }
            button.textContent = reader.dataset.copiedLabel;
            window.setTimeout(() => {
              button.textContent = reader.dataset.copyLabel;
            }, 1400);
          });
          pre.append(button);
        });
      }
    });
  };
  initReportReaders();

  const openRecordPanel = (url, trigger) => {
    if (!drawer) return;
    panelReturnFocus = trigger || null;
    drawer.hidden = false;
    document.body.classList.add('drawer-modal-open');
    drawerBody.replaceChildren();
    if (drawerLoading) drawerLoading.hidden = false;
    fetch(url)
      .then((response) => {
        if (isSignInRedirect(response)) {
          window.location.assign('/login');
          return Promise.reject(401);
        }
        return response.ok ? response.text() : Promise.reject(response.status);
      })
      .then((markup) => {
        if (drawerLoading) drawerLoading.hidden = true;
        // Server-rendered fragment from our own origin, already escaped by Jinja.
        drawerBody.innerHTML = markup;
        bindRecordPanel();
        initReportReaders(drawerBody);
        drawerBody.querySelector('[data-drawer-tab]')?.focus();
      })
      .catch((reason) => {
        if (drawerLoading) drawerLoading.hidden = true;
        if (reason === 401) return;
        // Fall back to the full page rather than leaving an empty drawer.
        window.location.href = url.replace('/panel', '');
      });
  };

  // Rows open on a plain click; links and controls inside them keep their own behaviour.
  const clickableRow = (row, open) => {
    row.classList.add('is-clickable');
    row.addEventListener('click', (event) => {
      if (plainClick(event) && !event.target.closest('a,button,input,select,textarea,label')) open();
    });
  };
  document.querySelectorAll('[data-record-panel]').forEach((row) => {
    clickableRow(row, () => openRecordPanel(row.dataset.recordPanel, row));
    row.querySelectorAll('a.strong-link').forEach((link) =>
      link.addEventListener('click', (event) => {
        if (!plainClick(event)) return;
        event.preventDefault();
        openRecordPanel(row.dataset.recordPanel, link);
      }),
    );
  });
  // Program rows are not vulnerabilities, so they navigate rather than preview.
  document.querySelectorAll('tr[data-row-href]').forEach((row) =>
    clickableRow(row, () => {
      window.location.href = row.dataset.rowHref;
    }),
  );

  // Command palette. Results are built with textContent because snippets can hold live payloads.
  const palette = document.querySelector('#palette');
  const paletteInput = document.querySelector('[data-palette-input]');
  const paletteResults = document.querySelector('[data-palette-results]');
  const paletteStatus = document.querySelector('[data-palette-status]');
  const paletteAll = document.querySelector('[data-palette-all]');
  let paletteRows = [];
  let paletteCursor = -1;
  let paletteTimer;
  let paletteSeq = 0;

  const paintCursor = () => {
    paletteRows.forEach((row, index) => {
      const active = index === paletteCursor;
      row.classList.toggle('active', active);
      row.setAttribute('aria-selected', String(active));
      if (active) row.scrollIntoView({ block: 'nearest' });
    });
  };

  const openPalette = () => {
    if (!palette) return;
    palette.hidden = false;
    document.body.classList.add('palette-open');
    paletteInput.focus();
    paletteInput.select();
    if (paletteInput.value.trim()) runPalette();
  };

  const closePalette = () => {
    if (!palette || palette.hidden) return;
    palette.hidden = true;
    document.body.classList.remove('palette-open');
    paletteRows = [];
    paletteCursor = -1;
  };

  const runPalette = () => {
    const query = paletteInput.value.trim();
    if (paletteAll) paletteAll.href = `/search?q=${encodeURIComponent(query)}`;
    if (!query) {
      paletteResults.replaceChildren();
      paletteRows = [];
      paletteCursor = -1;
      return;
    }
    const seq = ++paletteSeq;
    fetch(`/api/search?q=${encodeURIComponent(query)}&limit=6`, { headers: { Accept: 'application/json' } })
      .then((response) => (response.ok ? response.json() : Promise.reject(response.status)))
      .then((data) => {
        // Ignore responses that arrive after a newer request.
        if (seq !== paletteSeq) return;
        renderPalette(data);
      })
      .catch(() => {
        if (seq !== paletteSeq) return;
        paletteResults.replaceChildren();
        if (paletteStatus) paletteStatus.textContent = '—';
      });
  };

  const renderPalette = (data) => {
    paletteResults.replaceChildren();
    paletteRows = [];
    paletteCursor = -1;

    (data.groups || []).forEach((group) => {
      const heading = document.createElement('p');
      heading.className = 'palette-group';
      heading.textContent =
        group.total > group.items.length ? `${group.label} · ${group.items.length}/${group.total}` : group.label;
      paletteResults.append(heading);

      group.items.forEach((item) => {
        const row = document.createElement('a');
        row.className = 'palette-row';
        row.href = item.url;
        row.setAttribute('role', 'option');

        const main = document.createElement('span');
        main.className = 'palette-row-main';
        const title = document.createElement('strong');
        title.textContent = item.title || '—';
        main.append(title);
        if (item.snippet) {
          const snippet = document.createElement('small');
          snippet.textContent = item.snippet;
          main.append(snippet);
        }
        row.append(main);

        if (item.meta) {
          const meta = document.createElement('span');
          meta.className = 'palette-row-meta';
          meta.textContent = item.meta;
          row.append(meta);
        }
        row.addEventListener('mouseenter', () => {
          paletteCursor = paletteRows.indexOf(row);
          paintCursor();
        });
        paletteResults.append(row);
        paletteRows.push(row);
      });
    });

    if (paletteStatus) {
      const warnings = data.warnings || [];
      paletteStatus.textContent = warnings.length
        ? `${paletteStatus.dataset.unknownLabel}: ${warnings.join(', ')}`
        : `${data.total || 0}`;
    }
    if (paletteRows.length) {
      paletteCursor = 0;
      paintCursor();
    }
  };

  paletteInput?.addEventListener('input', () => {
    clearTimeout(paletteTimer);
    paletteTimer = setTimeout(runPalette, 160);
  });
  paletteInput?.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (!paletteRows.length) return;
      const step = event.key === 'ArrowDown' ? 1 : -1;
      paletteCursor = (paletteCursor + step + paletteRows.length) % paletteRows.length;
      paintCursor();
      return;
    }
    if (event.key === 'Enter') {
      event.preventDefault();
      const row = paletteRows[paletteCursor];
      // With no row selected, Enter opens the full results page.
      window.location.href = row ? row.href : `/search?q=${encodeURIComponent(paletteInput.value.trim())}`;
    }
  });
  document.querySelectorAll('[data-palette-close]').forEach((node) => node.addEventListener('click', closePalette));
  // The sidebar search box opens the palette.
  document.querySelectorAll('[data-palette-open]').forEach((node) => {
    node.addEventListener('focus', () => {
      node.blur();
      openPalette();
    });
  });

  document.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      const onLookupPage = document.querySelector('.lookup-field [data-global-search]');
      if (onLookupPage) {
        onLookupPage.focus();
        onLookupPage.select?.();
        return;
      }
      openPalette();
      return;
    }
    if (event.key === 'Escape' && palette && !palette.hidden) {
      event.preventDefault();
      closePalette();
      return;
    }
    if (event.key === 'Escape' && drawer && !drawer.hidden) {
      event.preventDefault();
      closeRecordPanel();
    }
  });

  const dialog = document.querySelector('#confirm-dialog');
  const dialogMessage = dialog?.querySelector('[data-confirm-message]');
  let confirmedAction = null;
  const confirmAction = (message, action) => {
    if (!dialog) {
      action();
      return;
    }
    dialogMessage.textContent = message;
    confirmedAction = action;
    dialog.showModal();
  };
  dialog?.addEventListener('close', () => {
    const action = confirmedAction;
    confirmedAction = null;
    if (dialog.returnValue === 'confirm') action?.();
  });

  // Forms marked data-confirm ask first, including forms loaded into the record drawer later.
  const confirmed = new WeakSet();
  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (!form.dataset?.confirm || confirmed.delete(form)) return;
    event.preventDefault();
    const { submitter } = event;
    confirmAction(form.dataset.confirm, () => {
      confirmed.add(form);
      form.requestSubmit(submitter);
    });
  });

  document.querySelectorAll('[data-auto-filter]').forEach((form) => {
    form.querySelectorAll('select, input[type="radio"]').forEach((field) => {
      field.addEventListener('change', () => form.requestSubmit());
    });
  });

  const recordTabs = [...document.querySelectorAll('[data-record-tab]')];
  if (recordTabs.length) {
    const panes = [...document.querySelectorAll('[data-record-pane]')];
    const activate = (name) => showTab(recordTabs, panes, name, 'recordTab', 'recordPane');
    recordTabs.forEach((tab) => tab.addEventListener('click', () => activate(tab.dataset.recordTab)));
    if (window.location.hash === '#evidence') activate('evidence');
  }

  const reportTemplates = {
    web: '# Summary\n\nDescribe the vulnerability and affected component.\n\n## Steps to reproduce\n\n1. \n2. \n3. \n\n## Proof of concept\n\n```http\nGET / HTTP/1.1\nHost: target.example\n```\n\n## Impact\n\nExplain the realistic security impact.\n\n## Remediation\n\nDescribe the recommended fix.\n',
    api: '# Summary\n\nDescribe the affected API behavior.\n\n## Endpoint\n\n`METHOD /api/path`\n\n## Steps to reproduce\n\n1. Obtain a valid session.\n2. Send the following request.\n3. Observe the unauthorized behavior.\n\n## Request\n\n```http\nGET /api/path HTTP/1.1\nHost: api.target.example\nAuthorization: Bearer …\n```\n\n## Response\n\n```json\n{}\n```\n\n## Impact\n\n\n## Remediation\n\n',
    mobile:
      '# Summary\n\nDescribe the mobile vulnerability and affected build.\n\n## Environment\n\n- Platform: Android / iOS\n- App version:\n- Device / OS:\n\n## Steps to reproduce\n\n1. \n2. \n3. \n\n## Technical details\n\n```text\nRelevant log or code\n```\n\n## Impact\n\n\n## Remediation\n\n',
    blank: '',
  };

  // Same rules as taxonomy.normalize_tag on the server.
  const normalizeTag = (value, maxLength) =>
    value
      .replace(/đ/gi, 'd')
      .normalize('NFKD')
      .replace(/[̀-ͯ]/g, '')
      .toLowerCase()
      .trim()
      .replace(/[\s_/]+/g, '-')
      .replace(/[^a-z0-9.+#-]/g, '')
      .replace(/-{2,}/g, '-')
      .replace(/^[-.]+|[-.]+$/g, '')
      .slice(0, maxLength);

  // Tag input: chips over the plain comma-separated field, which stays the submitted value.
  document.querySelectorAll('[data-tag-input]').forEach((field) => {
    const maxTags = Number(field.dataset.maxTags);
    const maxLength = Number(field.dataset.maxLength);
    const entry = document.createElement('input');
    entry.type = 'text';
    entry.className = 'tag-entry';
    entry.id = field.id;
    entry.placeholder = field.placeholder;
    entry.autocomplete = 'off';
    if (field.getAttribute('list')) entry.setAttribute('list', field.getAttribute('list'));
    const chips = document.createElement('span');
    chips.className = 'tag-chips';
    const box = document.createElement('div');
    box.className = 'tag-field';
    box.append(chips, entry);
    field.removeAttribute('id');
    field.removeAttribute('list');
    field.type = 'hidden';
    field.after(box);

    const parse = (raw) =>
      raw
        .split(',')
        .map((value) => normalizeTag(value, maxLength))
        .filter(Boolean);
    let tags = parse(field.value);
    const render = (changed) => {
      chips.replaceChildren(
        ...tags.map((tag) => {
          const chip = document.createElement('span');
          chip.className = 'tag-chip';
          const label = document.createElement('span');
          label.textContent = tag;
          const remove = document.createElement('button');
          remove.type = 'button';
          remove.textContent = '×';
          remove.setAttribute('aria-label', `${field.dataset.removeLabel} ${tag}`);
          remove.addEventListener('click', () => {
            tags = tags.filter((item) => item !== tag);
            render(true);
            entry.focus();
          });
          chip.append(label, remove);
          return chip;
        }),
      );
      field.value = tags.join(', ');
      if (changed) field.dispatchEvent(new Event('input', { bubbles: true }));
    };
    const add = (raw) => {
      parse(raw).forEach((tag) => {
        if (!tags.includes(tag) && tags.length < maxTags) tags.push(tag);
      });
      entry.value = '';
      render(true);
    };
    entry.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ',') {
        event.preventDefault();
        if (entry.value.trim()) add(entry.value);
      } else if (event.key === 'Backspace' && !entry.value && tags.length) {
        tags.pop();
        render(true);
      }
    });
    entry.addEventListener('input', (event) => {
      // A pasted list or a picked suggestion becomes tags straight away.
      if (entry.value.includes(',') || event.inputType === 'insertReplacementText' || !event.inputType) add(entry.value);
    });
    entry.addEventListener('blur', () => {
      if (entry.value.trim()) add(entry.value);
    });
    field.form?.addEventListener('submit', () => {
      if (entry.value.trim()) add(entry.value);
    });
    box.addEventListener('click', (event) => {
      if (event.target === box || event.target === chips) entry.focus();
    });
    render(false);
  });

  const editor = document.querySelector('[data-markdown-form]');
  if (editor) {
    const input = editor.querySelector('[data-markdown-input]');
    const writePane = editor.querySelector('[data-editor-pane="write"]');
    const previewPane = editor.querySelector('[data-editor-pane="preview"]');
    const tabs = editor.querySelectorAll('[data-editor-tab]');
    const status = editor.querySelector('[data-editor-status]');
    const markDirty = () => {
      status.textContent = editor.dataset.unsaved;
      status.classList.add('dirty');
    };
    const notice = (className, text) => {
      const element = document.createElement('div');
      element.className = className;
      element.textContent = text;
      return element;
    };

    editor.querySelectorAll('input, select, textarea').forEach((field) => {
      if (field.name !== 'csrf') field.addEventListener('input', markDirty);
    });
    editor.addEventListener('submit', () => {
      status.textContent = editor.dataset.ready;
      status.classList.remove('dirty');
    });
    editor.addEventListener('keydown', (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
        event.preventDefault();
        editor.requestSubmit();
      }
    });

    const activate = async (name) => {
      tabs.forEach((tab) => tab.classList.toggle('active', tab.dataset.editorTab === name));
      writePane.classList.toggle('active', name === 'write');
      previewPane.classList.toggle('active', name === 'preview');
      if (name === 'preview') {
        previewPane.replaceChildren(notice('preview-placeholder', editor.dataset.rendering));
        const response = await postForm('/markdown/preview', { markdown: input.value });
        if (isSignInRedirect(response)) {
          // Stay on the page so the unsaved draft is kept.
          previewPane.replaceChildren(notice('alert danger', editor.dataset.sessionExpired));
        } else if (response.ok) {
          previewPane.innerHTML = await response.text();
        } else {
          previewPane.replaceChildren(notice('alert danger', editor.dataset.previewFailed));
        }
      }
    };
    tabs.forEach((tab) => tab.addEventListener('click', () => activate(tab.dataset.editorTab)));

    const insertAtCursor = (text) => {
      const start = input.selectionStart;
      input.value = `${input.value.slice(0, start)}${text}${input.value.slice(input.selectionEnd)}`;
      input.selectionStart = input.selectionEnd = start + text.length;
      input.focus();
      markDirty();
    };
    input.addEventListener('keydown', (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
        event.preventDefault();
        activate('preview');
      }
      if (event.key === 'Tab') {
        event.preventDefault();
        insertAtCursor('  ');
      }
    });

    const templateSelect = editor.querySelector('[data-report-template]');
    editor.querySelector('[data-apply-template]')?.addEventListener('click', () => {
      const apply = () => {
        input.value = reportTemplates[templateSelect.value];
        markDirty();
        input.focus();
      };
      if (input.value.trim()) confirmAction(editor.dataset.confirmTemplate, apply);
      else apply();
    });

    editor.querySelectorAll('[data-insert-evidence]').forEach((button) =>
      button.addEventListener('click', () => {
        insertAtCursor(`\n![${button.dataset.name}](${button.dataset.url})\n`);
        activate('write');
      }),
    );

    const fileInput = editor.querySelector('[data-file-input]');
    const pending = editor.querySelector('[data-pending-files]');
    const renderPending = () => {
      const rows = [...(fileInput.files || [])].map((file) => {
        let preview;
        if (file.type.startsWith('image/')) {
          preview = document.createElement('img');
          preview.src = URL.createObjectURL(file);
          preview.alt = '';
        } else if (file.type.startsWith('video/')) {
          preview = document.createElement('video');
          preview.src = URL.createObjectURL(file);
          preview.muted = true;
        } else {
          preview = fileBadge(file.name.split('.').pop().slice(0, 4).toUpperCase());
        }
        return fileRow(preview, file, `${kilobytes(file)} · ${editor.dataset.readyToUpload}`);
      });
      pending.replaceChildren(...rows);
      if (rows.length) markDirty();
    };
    fileInput?.addEventListener('change', renderPending);
    bindDropZone(editor.querySelector('[data-drop-zone]'), fileInput, renderPending);

    // Related-entry suggestions shown as chips. Accepting one selects it in the fallback
    // <select>, which is what the form posts.
    const relate = editor.querySelector('[data-relate]');
    if (relate) {
      const chips = relate.querySelector('[data-relate-chips]');
      const select = relate.querySelector('[data-relate-select]');
      const currentId = relate.dataset.currentId || '';
      const noneLabel = relate.dataset.labelNone;
      const titleField = editor.querySelector('#title');
      const bugField = editor.querySelector('#bug-type');
      const techField = editor.querySelector('#technology');
      const cweField = editor.querySelector('#cwe');
      const summaryField = editor.querySelector('#summary');
      const tagsField = editor.querySelector('input[name="tags"]');
      const dismissed = new Set();
      const isRelated = (id) => [...select.options].some((option) => option.value === id && option.selected);
      const setRelated = (id, on) => {
        [...select.options].forEach((option) => {
          if (option.value === id) option.selected = on;
        });
      };
      const showEmpty = () => {
        const empty = document.createElement('p');
        empty.className = 'relate-empty';
        empty.textContent = noneLabel;
        chips.replaceChildren(empty);
      };
      const renderChips = (candidates) => {
        const shown = candidates.filter((item) => !dismissed.has(item.id) && !isRelated(item.id));
        if (!shown.length) {
          showEmpty();
          return;
        }
        chips.replaceChildren();
        shown.forEach((item) => {
          const chip = document.createElement('span');
          chip.className = 'relate-chip';
          const label = document.createElement('span');
          label.className = 'relate-chip-title';
          label.textContent = item.title;
          const reasons = (item.reasons || [])
            .map((reason) => relate.getAttribute(`data-reason-${reason}`))
            .filter(Boolean);
          chip.title = reasons.join(' · ');
          const meta = document.createElement('small');
          meta.className = 'relate-chip-meta';
          meta.textContent = reasons.join(' · ');
          const accept = document.createElement('button');
          accept.type = 'button';
          accept.className = 'relate-chip-accept';
          accept.textContent = relate.dataset.labelAccept;
          accept.addEventListener('click', () => {
            setRelated(item.id, true);
            markDirty();
            chip.remove();
            if (!chips.querySelector('.relate-chip')) showEmpty();
          });
          const dismiss = document.createElement('button');
          dismiss.type = 'button';
          dismiss.className = 'relate-chip-dismiss';
          dismiss.textContent = relate.dataset.labelDismiss;
          dismiss.setAttribute('aria-label', relate.dataset.labelDismiss);
          dismiss.addEventListener('click', () => {
            dismissed.add(item.id);
            chip.remove();
            if (!chips.querySelector('.relate-chip')) showEmpty();
          });
          chip.append(label, meta, accept, dismiss);
          chips.append(chip);
        });
      };
      const fetchCandidates = async () => {
        try {
          const response = await postForm('/knowledge/candidates', {
            current_id: currentId,
            cwe: cweField?.value || '',
            bug_type: bugField?.value || '',
            technology: techField?.value || '',
            title: titleField?.value || '',
            summary: summaryField?.value || '',
            tags: tagsField?.value || '',
          });
          if (!response.ok) return;
          const data = await response.json();
          renderChips(data.candidates || []);
        } catch (_error) {
          /* keep the current chips on network errors */
        }
      };
      let debounce;
      const schedule = () => {
        clearTimeout(debounce);
        debounce = setTimeout(fetchCandidates, 400);
      };
      [cweField, bugField, techField, titleField, summaryField, tagsField].forEach((field) => {
        field?.addEventListener('input', schedule);
        field?.addEventListener('change', schedule);
      });
      // Run once so an existing entry shows suggestions immediately.
      if ((cweField?.value || techField?.value || titleField?.value || '').trim()) fetchCandidates();
    }
  }

  document.querySelectorAll('[data-file-input]:not([multiple])').forEach((input) =>
    input.addEventListener('change', () => {
      const label = input.closest('label')?.querySelector('span');
      if (label && input.files[0]) label.textContent = input.files[0].name;
    }),
  );

  const importForm = document.querySelector('[data-import-form]');
  if (importForm) {
    const input = importForm.querySelector('[data-import-input]');
    const prompt = importForm.querySelector('[data-import-prompt]');
    const selected = importForm.querySelector('[data-import-selected]');
    const submit = importForm.querySelector('[data-import-submit]');
    const error = importForm.querySelector('[data-import-error]');
    const promptDefault = prompt?.textContent || '';

    const render = () => {
      const file = input.files && input.files[0];
      selected.replaceChildren();
      if (!file) {
        selected.hidden = true;
        submit.disabled = true;
        if (prompt) prompt.textContent = promptDefault;
        return;
      }
      selected.append(fileRow(fileBadge('MD'), file, kilobytes(file)));
      selected.hidden = false;
      if (prompt) prompt.textContent = file.name;
      // Extension hint only; the server validates the file.
      const isMarkdown = /\.md$/i.test(file.name);
      if (error) {
        error.textContent = isMarkdown ? '' : importForm.dataset.extensionError;
        error.hidden = isMarkdown;
      }
      submit.disabled = !isMarkdown;
    };

    input?.addEventListener('change', render);
    bindDropZone(importForm.querySelector('[data-import-drop]'), input, render, { single: true });
    render();
  }

  // WebMCP: register the agent tools for an in-browser agent acting as the signed-in user.
  // The catalogue comes from the server, so browser and MCP clients always match.
  const modelContext = document.modelContext || navigator.modelContext;
  // Register once per tab, not again inside the drawer's editor frame.
  if (modelContext?.registerTool && csrfToken && window.top === window) {
    // The current spec returns the tool's JSON value; the older navigator.modelContext
    // preview expects MCP content blocks.
    const legacy = !document.modelContext;
    const unregister = new AbortController();
    const callTool = async (name, input) => {
      const response = await fetch('/api/agent/call', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ tool: name, arguments: input || {} }),
      });
      const payload = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
      if (!legacy) return payload;
      return { content: [{ type: 'text', text: JSON.stringify(payload) }], isError: !response.ok };
    };
    fetch('/api/agent/tools', { headers: { Accept: 'application/json' } })
      .then((response) => (response.ok ? response.json() : Promise.reject(response.status)))
      .then(({ tools }) => {
        tools.forEach((tool) => {
          const definition = { ...tool, execute: (input) => callTool(tool.name, input) };
          try {
            const registered = modelContext.registerTool(definition, { signal: unregister.signal });
            registered?.catch?.(() => {});
          } catch (error) {
            console.warn(`WebMCP: could not register ${tool.name}`, error);
          }
        });
      })
      .catch(() => {});
    window.addEventListener('pagehide', () => unregister.abort(), { once: true });
  }
})();

// Enhance readable static examples into keyboard-accessible tabs.
for (const group of document.querySelectorAll('[data-tabs]')) {
  const list = group.querySelector('.demo-tabs');
  const tabs = [...group.querySelectorAll('[data-tab]')];
  const panels = [...group.querySelectorAll('[data-panel]')];
  list.setAttribute('role', 'tablist');
  const horizontalTabs = window.matchMedia('(min-width: 768px) and (max-width: 900px)');
  const updateOrientation = () => {
    list.setAttribute('aria-orientation', horizontalTabs.matches ? 'horizontal' : 'vertical');
  };
  horizontalTabs.addEventListener('change', updateOrientation);
  updateOrientation();
  const activate = (tab, focus = false) => {
    for (const item of tabs) {
      const selected = item === tab;
      item.setAttribute('aria-selected', String(selected));
      item.tabIndex = selected ? 0 : -1;
    }
    for (const panel of panels) panel.hidden = panel.dataset.panel !== tab.dataset.tab;
    if (focus) tab.focus();
  };
  for (const [index, tab] of tabs.entries()) {
    tab.setAttribute('role', 'tab');
    tab.setAttribute('aria-controls', `panel-${tab.dataset.tab}`);
    tab.addEventListener('click', () => activate(tab));
    tab.addEventListener('keydown', (event) => {
      let next;
      if (event.key === 'ArrowDown' || event.key === 'ArrowRight') next = (index + 1) % tabs.length;
      if (event.key === 'ArrowUp' || event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
      if (event.key === 'Home') next = 0;
      if (event.key === 'End') next = tabs.length - 1;
      if (next === undefined) return;
      event.preventDefault();
      activate(tabs[next], true);
    });
  }
  for (const panel of panels) {
    panel.setAttribute('role', 'tabpanel');
    panel.tabIndex = 0;
  }
  activate(tabs[0]);
}

for (const button of document.querySelectorAll('[data-copy-target]')) {
  button.addEventListener('click', async () => {
    const code = document.getElementById(button.dataset.copyTarget);
    const status = document.getElementById('copy-status');
    button.disabled = true;
    button.textContent = 'Copying…';
    try {
      await navigator.clipboard.writeText(code.textContent);
      button.textContent = 'Copied';
      status.textContent = 'Quickstart commands copied to clipboard.';
    } catch {
      button.textContent = 'Select and copy';
      const range = document.createRange();
      range.selectNodeContents(code);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      status.textContent = 'Clipboard access is unavailable. Commands selected; use your browser’s copy command.';
    } finally {
      button.disabled = false;
    }
  });
}

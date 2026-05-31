// UI wiring: read file locally, extract addresses, look up balances, render.
(function () {
  'use strict';

  var drop = document.getElementById('drop');
  var fileInput = document.getElementById('file');
  var statusEl = document.getElementById('status');
  var summaryEl = document.getElementById('summary');
  var table = document.getElementById('results');
  var tbody = table.querySelector('tbody');
  var onlyWithBalance = document.getElementById('onlyWithBalance');
  var explorerSel = document.getElementById('explorer');

  var EXPLORERS = {
    mempool: {
      api: function (a) { return 'https://mempool.space/api/address/' + a; },
      link: function (a) { return 'https://mempool.space/address/' + a; }
    },
    blockstream: {
      api: function (a) { return 'https://blockstream.info/api/address/' + a; },
      link: function (a) { return 'https://blockstream.info/address/' + a; }
    }
  };

  function setStatus(msg, isError) {
    statusEl.hidden = false;
    statusEl.textContent = msg;
    statusEl.classList.toggle('error', !!isError);
  }

  function satsToBtc(sats) { return (sats / 1e8).toFixed(8); }

  // --- file handling -------------------------------------------------------
  drop.addEventListener('click', function () { fileInput.click(); });
  drop.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
  });
  drop.addEventListener('dragover', function (e) { e.preventDefault(); drop.classList.add('drag'); });
  drop.addEventListener('dragleave', function () { drop.classList.remove('drag'); });
  drop.addEventListener('drop', function (e) {
    e.preventDefault();
    drop.classList.remove('drag');
    if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener('change', function () {
    if (fileInput.files.length) handleFile(fileInput.files[0]);
  });

  function handleFile(file) {
    table.hidden = true;
    tbody.innerHTML = '';
    summaryEl.hidden = true;
    setStatus('Reading "' + file.name + '" (' + Math.round(file.size / 1024) + ' KB) locally…');
    var reader = new FileReader();
    reader.onerror = function () { setStatus('Could not read the file.', true); };
    reader.onload = function () { processBuffer(reader.result); };
    reader.readAsArrayBuffer(file);
  }

  async function processBuffer(arrayBuffer) {
    try {
      setStatus('Extracting public addresses in your browser… (nothing has been uploaded)');
      var addresses = await walletParser.extractAddresses(arrayBuffer);
      if (!addresses.length) {
        setStatus('No recognizable Bitcoin addresses found. If this wallet is encrypted, ' +
          'public keys may be unreadable without unlocking it in Bitcoin Core first.', true);
        return;
      }
      setStatus('Found ' + addresses.length + ' candidate addresses. Looking up balances on ' +
        explorerSel.value + '… (only the public addresses are sent)');
      await lookupAndRender(addresses);
    } catch (err) {
      setStatus('Error while parsing: ' + (err && err.message ? err.message : err), true);
    }
  }

  // --- balance lookup ------------------------------------------------------
  async function fetchAddress(api, address) {
    for (var attempt = 0; attempt < 3; attempt++) {
      try {
        var res = await fetch(api(address), { headers: { 'Accept': 'application/json' } });
        if (res.status === 429) { await sleep(1000 * (attempt + 1)); continue; }
        if (!res.ok) return null;
        var j = await res.json();
        var chain = j.chain_stats || {};
        var mem = j.mempool_stats || {};
        var balance = (chain.funded_txo_sum || 0) - (chain.spent_txo_sum || 0)
          + (mem.funded_txo_sum || 0) - (mem.spent_txo_sum || 0);
        var txs = (chain.tx_count || 0) + (mem.tx_count || 0);
        return { balance: balance, txs: txs };
      } catch (e) {
        await sleep(500 * (attempt + 1));
      }
    }
    return null;
  }

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  async function mapPool(items, concurrency, fn, onProgress) {
    var idx = 0, done = 0;
    var results = new Array(items.length);
    async function worker() {
      while (idx < items.length) {
        var cur = idx++;
        results[cur] = await fn(items[cur], cur);
        onProgress(++done, items.length);
      }
    }
    var workers = [];
    for (var w = 0; w < Math.min(concurrency, items.length); w++) workers.push(worker());
    await Promise.all(workers);
    return results;
  }

  async function lookupAndRender(addresses) {
    var exp = EXPLORERS[explorerSel.value];
    var stats = await mapPool(addresses, 4, function (item) {
      return fetchAddress(exp.api, item.address);
    }, function (done, total) {
      setStatus('Checked ' + done + ' / ' + total + ' addresses…');
    });

    var rows = [];
    var totalSats = 0;
    var requireBalance = onlyWithBalance.checked;
    for (var i = 0; i < addresses.length; i++) {
      var s = stats[i];
      if (!s) continue;                       // lookup failed
      if (requireBalance ? s.balance <= 0 : s.txs <= 0) continue;
      rows.push({ a: addresses[i], s: s });
      totalSats += s.balance;
    }

    rows.sort(function (x, y) { return y.s.balance - x.s.balance; });
    render(rows, exp, totalSats);
  }

  function render(rows, exp, totalSats) {
    tbody.innerHTML = '';
    if (!rows.length) {
      setStatus('Extraction succeeded, but none of the found addresses ' +
        (onlyWithBalance.checked ? 'hold a balance.' : 'show any on-chain activity.'));
      table.hidden = true;
      summaryEl.hidden = true;
      return;
    }
    rows.forEach(function (r) {
      var tr = document.createElement('tr');
      if (r.s.balance > 0) tr.className = 'has-balance';

      var tdA = document.createElement('td');
      tdA.className = 'addr';
      tdA.textContent = r.a.address;

      var tdT = document.createElement('td');
      tdT.textContent = r.a.type;

      var tdB = document.createElement('td');
      tdB.className = 'num bal';
      tdB.textContent = satsToBtc(r.s.balance);

      var tdX = document.createElement('td');
      tdX.className = 'num';
      tdX.textContent = r.s.txs;

      var tdL = document.createElement('td');
      var link = document.createElement('a');
      link.href = exp.link(r.a.address);
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.textContent = 'view ↗';
      tdL.appendChild(link);

      tr.append(tdA, tdT, tdB, tdX, tdL);
      tbody.appendChild(tr);
    });

    table.hidden = false;
    summaryEl.hidden = false;
    summaryEl.innerHTML = 'Showing <strong>' + rows.length + '</strong> address(es). ' +
      'Total balance: <span class="total">' + satsToBtc(totalSats) + ' BTC</span>.';
    setStatus('Done. Your file was never uploaded.');
  }
})();

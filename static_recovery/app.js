let step = 1;
let backupMeta = null;
let verifiedShards = [];
let pendingShard = null;
let pendingShardLabel = '';
let lastPlaintext = null;

async function readApiResponse(res) {
    const text = await res.text();
    if (!text) return {};
    try {
        return JSON.parse(text);
    } catch {
        throw new Error(text);
    }
}

function goStep(n) {
    step = n;
    for (let i = 1; i <= 4; i++) {
        const p = document.getElementById('panel-' + i);
        if (p) p.style.display = i === n ? 'block' : 'none';
    }
    document.querySelectorAll('.step-pill').forEach((el) => {
        el.classList.toggle('active', el.dataset.step === String(n));
    });
    if (n === 4) {
        syncPassphraseUi();
    }
}

function hasRecoveryPassphrase() {
    const input = document.getElementById('passphrase-input');
    return Boolean(input && input.value.trim());
}

function syncPassphraseUi() {
    const decryptBtn = document.getElementById('decrypt-btn');
    const hint = document.getElementById('passphrase-status');
    const input = document.getElementById('passphrase-input');
    const rawValue = input ? input.value : '';
    const hasPassphrase = Boolean(rawValue.trim());

    if (decryptBtn) decryptBtn.disabled = !hasPassphrase;
    if (hint) {
        hint.textContent = hasPassphrase
            ? 'Passphrase captured. Recovery only works with the exact passphrase used at backup time.'
            : 'Required: without the backup passphrase, the encrypted file key cannot be derived for recovery.';
    }
}

function resetRecovery() {
    backupMeta = null;
    verifiedShards = [];
    pendingShard = null;
    pendingShardLabel = '';
    lastPlaintext = null;
    document.getElementById('sk-input').value = '';
    document.getElementById('sign-pk-input').value = '';
    document.getElementById('passphrase-input').value = '';
    document.getElementById('sign-pk-file').value = '';
    document.getElementById('shard-file').value = '';
    document.getElementById('shard-pending-hint').textContent = 'No file selected';
    document.getElementById('verify-shard-btn').disabled = true;
    document.getElementById('backup-meta').style.display = 'none';
    document.getElementById('verify-status').style.display = 'none';
    document.getElementById('shard-staging').innerHTML = '';
    document.getElementById('shard-count-hint').textContent = '0 verified shard(s)';
    document.getElementById('btn-next-shards').disabled = true;
    document.getElementById('decrypt-status').style.display = 'none';
    document.getElementById('result-preview').style.display = 'none';
    document.getElementById('dl-plain-btn').style.display = 'none';
    syncPassphraseUi();
    goStep(1);
}

function getSignPk() {
    return document.getElementById('sign-pk-input').value.trim();
}

function parseSignedShard(obj) {
    if (!obj || typeof obj.index !== 'number' || !obj.data || !obj.signature || !obj.params) {
        throw new Error('Invalid signed shard: expected index, data, signature, and embedded params.');
    }
    return obj;
}

function shardsConsistent(a, b) {
    return (
        JSON.stringify(a.params) === JSON.stringify(b.params) &&
        a.total === b.total &&
        a.threshold === b.threshold
    );
}

function updateShardUi() {
    const box = document.getElementById('shard-staging');
    box.innerHTML = '';
    verifiedShards.forEach((s, idx) => {
        const row = document.createElement('div');
        row.className = 'shard-chip';
        row.innerHTML = `<div class="shard-chip-info"><span class="shard-chip-index">Shard ${s.index} — verified</span><span class="shard-chip-source">${s.sourceName}</span></div>`;
        const rm = document.createElement('button');
        rm.type = 'button';
        rm.className = 'btn btn-ghost btn-sm';
        rm.textContent = 'Remove';
        rm.onclick = () => {
            verifiedShards.splice(idx, 1);
            if (verifiedShards.length === 0) {
                backupMeta = null;
                document.getElementById('backup-meta').style.display = 'none';
            }
            updateShardUi();
        };
        row.appendChild(rm);
        box.appendChild(row);
    });

    const need = backupMeta ? backupMeta.threshold : 0;
    document.getElementById('shard-count-hint').textContent =
        `${verifiedShards.length} verified shard(s)${backupMeta ? ` — need at least ${need} of ${backupMeta.total_shards}` : ''}`;
    document.getElementById('btn-next-shards').disabled =
        !backupMeta || verifiedShards.length < backupMeta.threshold;
}

function setPendingShard(obj, label) {
    pendingShard = obj;
    pendingShardLabel = label;
    document.getElementById('shard-pending-hint').textContent = label;
    document.getElementById('verify-shard-btn').disabled = !pendingShard;
}

function ingestShardFile(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
        try {
            const text = typeof reader.result === 'string' ? reader.result : '';
            const obj = parseSignedShard(JSON.parse(text));
            setPendingShard(obj, file.name);
        } catch (e) {
            pendingShard = null;
            document.getElementById('verify-shard-btn').disabled = true;
            window.alert(String(e.message || e));
        }
    };
    reader.readAsText(file);
}

async function verifyPendingShard() {
    const sk = document.getElementById('sk-input').value.trim();
    const signPk = getSignPk();
    if (!sk) {
        window.alert('Enter the decapsulation key first (step 1).');
        goStep(1);
        return;
    }
    if (!signPk) {
        window.alert('Enter the signing public key first (step 2).');
        goStep(2);
        return;
    }
    if (!pendingShard) {
        window.alert('Select a shard file first.');
        return;
    }

    const status = document.getElementById('verify-status');
    status.style.display = 'block';
    status.className = 'status-msg';
    status.textContent = 'Verifying signature…';
    document.getElementById('verify-shard-btn').disabled = true;

    try {
        const res = await fetch('/api/verify-shard', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                secret_key_b64: sk,
                signing_public_key_b64: signPk,
                shard: pendingShard,
            }),
        });
        const data = await readApiResponse(res);
        if (!res.ok || !data.success || !data.valid) {
            throw new Error(data.error || 'Shard verification failed');
        }

        if (verifiedShards.some((s) => s.index === pendingShard.index)) {
            throw new Error(`Shard index ${pendingShard.index} is already verified.`);
        }
        if (verifiedShards.length > 0 && !shardsConsistent(verifiedShards[0], pendingShard)) {
            throw new Error('This shard does not match the embedded backup data from earlier shards.');
        }

        verifiedShards.push({
            ...pendingShard,
            sourceName: pendingShardLabel,
        });
        if (!backupMeta) {
            backupMeta = {
                threshold: data.threshold,
                total_shards: data.total_shards,
            };
            const meta = document.getElementById('backup-meta');
            meta.style.display = 'block';
            meta.textContent = data.message || `Backup is ${data.threshold}-of-${data.total_shards}. Upload ${data.threshold} verified shards to decrypt.`;
            document.getElementById('shard-upload-desc').textContent =
                `Verified ${data.threshold}-of-${data.total_shards}. Add ${Math.max(0, data.threshold - verifiedShards.length)} more distinct shard(s), verifying each.`;
        }

        status.className = 'status-msg success';
        status.textContent = `Shard ${pendingShard.index} verified successfully.`;
        pendingShard = null;
        pendingShardLabel = '';
        document.getElementById('shard-pending-hint').textContent = 'No file selected — add another shard';
        document.getElementById('shard-file').value = '';
        updateShardUi();
    } catch (e) {
        status.className = 'status-msg error';
        status.textContent = String(e.message || e);
    } finally {
        document.getElementById('verify-shard-btn').disabled = !pendingShard;
    }
}

async function runDecrypt() {
    const sk = document.getElementById('sk-input').value.trim();
    const signPk = getSignPk();
    if (!sk) {
        window.alert('Enter the decapsulation key first.');
        goStep(1);
        return;
    }
    if (!signPk) {
        window.alert('Enter the signing public key first.');
        goStep(2);
        return;
    }
    if (!backupMeta || verifiedShards.length < backupMeta.threshold) {
        window.alert(`Need at least ${backupMeta ? backupMeta.threshold : '?'} verified shards.`);
        goStep(3);
        return;
    }
    const passphrase = document.getElementById('passphrase-input').value;
    if (!passphrase.trim()) {
        window.alert('Enter the backup passphrase.');
        return;
    }

    const status = document.getElementById('decrypt-status');
    const btn = document.getElementById('decrypt-btn');
    status.style.display = 'block';
    status.className = 'status-msg';
    status.textContent = 'Decrypting…';
    btn.disabled = true;

    const shardsPayload = verifiedShards.map((s) => ({
        index: s.index,
        total: s.total,
        threshold: s.threshold,
        data: s.data,
        params: s.params,
        signature: s.signature,
        encapsulation_key_b64: s.encapsulation_key_b64,
        original_filename: s.original_filename,
    }));

    try {
        const res = await fetch('/api/decrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                secret_key_b64: sk,
                signing_public_key_b64: signPk,
                passphrase: passphrase,
                shards: shardsPayload,
            }),
        });
        const data = await readApiResponse(res);
        if (!res.ok || !data.success) {
            throw new Error(data.error || 'Decryption failed');
        }
        lastPlaintext = data.plaintext;
        status.className = 'status-msg success';
        status.textContent = 'Decryption succeeded.';
        const prev = document.getElementById('result-preview');
        prev.style.display = 'block';
        prev.textContent = data.plaintext;
        const outName = (data.original_filename || 'recovered.json').replace(/[^\w.\-]+/g, '_');
        document.getElementById('dl-plain-btn').style.display = 'inline-flex';
        document.getElementById('dl-plain-btn').dataset.filename = outName;
    } catch (e) {
        status.className = 'status-msg error';
        status.textContent = String(e.message || e);
    } finally {
        syncPassphraseUi();
    }
}

function downloadPlain() {
    if (!lastPlaintext) return;
    const name = document.getElementById('dl-plain-btn').dataset.filename || 'recovered.json';
    const blob = new Blob([lastPlaintext], { type: 'application/json;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
}

document.addEventListener('DOMContentLoaded', () => {
    const passphraseInput = document.getElementById('passphrase-input');
    const syncRecoveryPassphrase = () => {
        document.getElementById('decrypt-status').style.display = 'none';
        syncPassphraseUi();
    };
    ['input', 'change', 'keyup', 'paste'].forEach((eventName) => {
        passphraseInput.addEventListener(eventName, syncRecoveryPassphrase);
    });

    document.getElementById('sign-pk-file').addEventListener('change', (e) => {
        const f = e.target.files && e.target.files[0];
        if (!f) return;
        const reader = new FileReader();
        reader.onload = () => {
            document.getElementById('sign-pk-input').value =
                typeof reader.result === 'string' ? reader.result.trim() : '';
        };
        reader.readAsText(f);
    });

    document.getElementById('shard-file').addEventListener('change', (e) => {
        const f = e.target.files && e.target.files[0];
        if (f) ingestShardFile(f);
    });

    const sd = document.getElementById('shard-drop');
    sd.addEventListener('dragover', (e) => {
        e.preventDefault();
        sd.classList.add('dragover');
    });
    sd.addEventListener('dragleave', () => sd.classList.remove('dragover'));
    sd.addEventListener('drop', (e) => {
        e.preventDefault();
        sd.classList.remove('dragover');
        const f = e.dataTransfer.files && e.dataTransfer.files[0];
        if (f) ingestShardFile(f);
    });

    syncPassphraseUi();
});

let step = 1;
let jsonText = '';
let originalFilename = '';
let signingSecretKeyB64 = '';
let signingPublicKeyB64 = '';
let signingKeysReady = false;

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
    if (n === 3) {
        syncPassphraseUi();
    }
    if (n === 4) {
        prepareSigningKeys();
    }
}

function hasBackupPassphrase() {
    const input = document.getElementById('passphrase-input');
    return Boolean(input && input.value.trim());
}

function syncPassphraseUi() {
    const nextBtn = document.getElementById('btn-next-3');
    const encryptBtn = document.getElementById('encrypt-run-btn');
    const hint = document.getElementById('passphrase-status');
    const input = document.getElementById('passphrase-input');
    const rawValue = input ? input.value : '';
    const hasPassphrase = Boolean(rawValue.trim());

    if (nextBtn) nextBtn.disabled = !hasPassphrase;
    if (encryptBtn) encryptBtn.disabled = !signingKeysReady || !hasPassphrase;
    if (hint) {
        hint.textContent = hasPassphrase
            ? 'Passphrase captured. Keep it safe: recovery requires the exact same passphrase.'
            : 'Required: this passphrase is part of the file-encryption key derivation shown in the backup flow.';
    }
}

function resetWizard() {
    jsonText = '';
    originalFilename = '';
    signingSecretKeyB64 = '';
    signingPublicKeyB64 = '';
    signingKeysReady = false;
    document.getElementById('pk-input').value = '';
    document.getElementById('passphrase-input').value = '';
    document.getElementById('json-name-hint').textContent = 'No file selected';
    document.getElementById('btn-next-2').disabled = true;
    document.getElementById('encrypt-status').style.display = 'none';
    document.getElementById('dl-area').style.display = 'none';
    document.getElementById('dl-list').innerHTML = '';
    document.getElementById('sign-key-area').style.display = 'none';
    document.getElementById('sign-pk-display').value = '';
    document.getElementById('sign-key-status').textContent = 'Preparing signing keys…';
    syncPassphraseUi();
    goStep(1);
}

function validateShardingAndGo() {
    const passphrase = document.getElementById('passphrase-input').value;
    if (!passphrase.trim()) {
        window.alert('Enter the backup passphrase.');
        return;
    }
    const total = parseInt(document.getElementById('total-shards').value, 10);
    const thr = parseInt(document.getElementById('threshold').value, 10);
    if (Number.isNaN(total) || Number.isNaN(thr)) {
        window.alert('Please enter valid numbers for total shards and threshold.');
        return;
    }
    if (thr < 1 || total < 1) {
        window.alert('Total shards and threshold must each be at least 1.');
        return;
    }
    if (thr > total) {
        window.alert('Threshold cannot be greater than total shards.');
        return;
    }
    if (total > 255) {
        window.alert('Total shards cannot exceed 255.');
        return;
    }
    const hint = document.getElementById('shard-hint');
    hint.style.display = 'block';
    hint.textContent = `You chose Shamir ${thr}-of-${total}: keep at least ${thr} distinct signed shard files to recover.`;
    goStep(4);
}

async function prepareSigningKeys() {
    const status = document.getElementById('sign-key-status');
    const area = document.getElementById('sign-key-area');
    const encryptBtn = document.getElementById('encrypt-run-btn');
    status.textContent = 'Generating Dilithium3 signing keypair…';
    area.style.display = 'none';
    encryptBtn.disabled = true;
    signingSecretKeyB64 = '';
    signingPublicKeyB64 = '';
    signingKeysReady = false;
    syncPassphraseUi();

    try {
        const res = await fetch('/api/signing-keygen', { method: 'POST' });
        const data = await readApiResponse(res);
        if (!res.ok || !data.success) {
            throw new Error(data.error || 'Signing key generation failed');
        }
        signingSecretKeyB64 = data.signing_secret_key_b64;
        signingPublicKeyB64 = data.signing_public_key_b64;
        signingKeysReady = true;
        document.getElementById('sign-pk-display').value = signingPublicKeyB64;
        area.style.display = 'block';
        status.textContent = 'Signing keys ready. Copy or download the public key before encrypting.';
    } catch (e) {
        signingKeysReady = false;
        status.textContent = String(e.message || e);
    } finally {
        syncPassphraseUi();
    }
}

function ingestJsonFile(file) {
    if (!file) return;
    originalFilename = file.name || 'document.json';
    const reader = new FileReader();
    reader.onload = () => {
        jsonText = typeof reader.result === 'string' ? reader.result : '';
        document.getElementById('json-name-hint').textContent = originalFilename;
        document.getElementById('btn-next-2').disabled = !jsonText.trim();
    };
    reader.readAsText(file);
}

async function runEncrypt() {
    const pk = document.getElementById('pk-input').value.trim();
    if (!pk) {
        window.alert('Paste the encapsulation (public) key first.');
        goStep(1);
        return;
    }
    if (!jsonText.trim()) {
        window.alert('Upload a JSON file first.');
        goStep(2);
        return;
    }
    if (!signingSecretKeyB64) {
        window.alert('Signing keys are not ready yet. Wait or go back and return to this step.');
        return;
    }
    const passphrase = document.getElementById('passphrase-input').value;
    if (!passphrase.trim()) {
        window.alert('Enter the backup passphrase (step 3).');
        goStep(3);
        return;
    }
    const total = parseInt(document.getElementById('total-shards').value, 10);
    const thr = parseInt(document.getElementById('threshold').value, 10);
    if (thr > total || thr < 1 || total < 1) {
        window.alert('Fix shard parameters.');
        goStep(3);
        return;
    }

    const status = document.getElementById('encrypt-status');
    const btn = document.getElementById('encrypt-run-btn');
    status.style.display = 'block';
    status.className = 'status-msg';
    status.textContent = 'Encrypting and signing shards…';
    btn.disabled = true;

    try {
        const res = await fetch('/api/encrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                public_key_b64: pk,
                signing_secret_key_b64: signingSecretKeyB64,
                signing_public_key_b64: signingPublicKeyB64,
                passphrase: passphrase,
                plaintext: jsonText,
                threshold: thr,
                total_shards: total,
                original_filename: originalFilename,
            }),
        });
        const data = await readApiResponse(res);
        if (!res.ok || !data.success) {
            throw new Error(data.error || 'Encryption failed');
        }
        if (data.signing_public_key_b64) {
            signingPublicKeyB64 = data.signing_public_key_b64;
            document.getElementById('sign-pk-display').value = signingPublicKeyB64;
        }
        status.className = 'status-msg success';
        status.textContent = 'Success. Download the signing public key and each signed shard below.';
        buildDownloadList(data);
        document.getElementById('dl-area').style.display = 'block';
    } catch (e) {
        status.className = 'status-msg error';
        status.textContent = String(e.message || e);
    } finally {
        syncPassphraseUi();
    }
}

function downloadBlob(filename, text) {
    const blob = new Blob([text], { type: 'application/json;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
}

function baseFilename() {
    const stem = (originalFilename || 'backup').replace(/\.[^/.]+$/, '');
    return stem.replace(/[^\w\-]+/g, '_') || 'backup';
}

function buildDownloadList(data) {
    const list = document.getElementById('dl-list');
    list.innerHTML = '';
    const stem = baseFilename();

    const pkBtn = document.createElement('button');
    pkBtn.type = 'button';
    pkBtn.className = 'btn btn-success btn-full';
    pkBtn.textContent = `Download signing public key (${stem}.sign_pk.b64)`;
    pkBtn.onclick = () => downloadBlob(`${stem}.sign_pk.b64`, signingPublicKeyB64);
    list.appendChild(pkBtn);

    (data.shards || []).forEach((shard) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'btn btn-ghost btn-full';
        b.style.borderColor = 'rgba(245, 158, 11, 0.25)';
        b.textContent = `Download signed shard ${shard.index} of ${shard.total} (${stem}.shard${shard.index}.json)`;
        b.onclick = () => {
            downloadBlob(`${stem}.shard${shard.index}.json`, JSON.stringify(shard, null, 2));
        };
        list.appendChild(b);
    });
}

document.addEventListener('DOMContentLoaded', () => {
    const passphraseInput = document.getElementById('passphrase-input');
    const syncBackupPassphrase = () => {
        document.getElementById('encrypt-status').style.display = 'none';
        syncPassphraseUi();
    };
    ['input', 'change', 'keyup', 'paste'].forEach((eventName) => {
        passphraseInput.addEventListener(eventName, syncBackupPassphrase);
    });

    document.getElementById('copy-sign-pk-btn').addEventListener('click', async () => {
        if (!signingPublicKeyB64) return;
        try {
            await navigator.clipboard.writeText(signingPublicKeyB64);
            window.alert('Signing public key copied to clipboard.');
        } catch {
            window.alert('Could not copy — select and copy from the text box.');
        }
    });
    document.getElementById('dl-sign-pk-btn').addEventListener('click', () => {
        if (!signingPublicKeyB64) return;
        downloadBlob(`${baseFilename()}.sign_pk.b64`, signingPublicKeyB64);
    });

    const input = document.getElementById('json-file');
    input.addEventListener('change', (e) => {
        const f = e.target.files && e.target.files[0];
        if (f) ingestJsonFile(f);
    });

    const dz = document.getElementById('json-drop');
    dz.addEventListener('dragover', (e) => {
        e.preventDefault();
        dz.classList.add('dragover');
    });
    dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
    dz.addEventListener('drop', (e) => {
        e.preventDefault();
        dz.classList.remove('dragover');
        const f = e.dataTransfer.files && e.dataTransfer.files[0];
        if (f) ingestJsonFile(f);
    });

    syncPassphraseUi();
});

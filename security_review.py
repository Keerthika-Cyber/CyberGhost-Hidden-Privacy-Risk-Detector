"""security_review.py — checks source files for privacy/security issues."""
import pathlib, re

base = pathlib.Path(__file__).parent

checks = {
    'index.html': base / 'index.html',
    'styles.css':  base / 'styles.css',
    'script.js':   base / 'script.js',
}

print('=== SECURITY REVIEW ===')
for name, path in checks.items():
    src = path.read_text(encoding='utf-8')
    print(f'\n--- {name} ---')

    # 1. innerHTML usage
    if 'innerHTML' in src:
        lines = [i+1 for i, l in enumerate(src.splitlines()) if 'innerHTML' in l]
        print(f'  WARNING: innerHTML at lines {lines}')
    else:
        print('  PASS: innerHTML not found')

    # 2. localStorage / sessionStorage
    for store in ['localStorage', 'sessionStorage']:
        if store in src:
            lines = [i+1 for i, l in enumerate(src.splitlines()) if store in l]
            print(f'  WARNING: {store} at lines {lines}')
        else:
            print(f'  PASS: {store} not found')

    # 3. console.log  
    clogs = [i+1 for i, l in enumerate(src.splitlines()) if 'console.log' in l]
    if clogs:
        print(f'  INFO: console.log at lines {clogs}')
    else:
        print('  PASS: no console.log calls')

    # 4. eval / document.write
    for danger in ['eval(', 'document.write(']:
        if danger in src:
            print(f'  WARNING: {danger} found!')
        else:
            print(f'  PASS: {danger} not found')

    # 5. External CDN/tracking scripts
    ext_scripts = re.findall(r'src=["\']https?://[^"\']+["\']', src)
    if ext_scripts:
        print(f'  WARNING: External script src: {ext_scripts}')
    else:
        print('  PASS: no external script src attributes')

    # 6. External CSS/font imports
    ext_css = re.findall(r'@import\s+["\']https?://[^"\']+["\']', src)
    if ext_css:
        print(f'  WARNING: External CSS imports: {ext_css}')
    else:
        print('  PASS: no external @import')

    # 7. Real private key markers
    if '-----BEGIN RSA PRIVATE KEY-----' in src or '-----BEGIN PRIVATE KEY-----' in src:
        print('  CRITICAL: PEM private key found in source!')
    else:
        print('  PASS: no real PEM private keys')

    # 8. Looks like a real API key (long alphanumeric not obviously a word)
    suspicious = re.findall(r'\b[A-Za-z0-9]{40,}\b', src)
    suspicious = [s for s in suspicious if not re.search(r'[A-Z][a-z]{3,}', s)]
    if suspicious:
        print(f'  INFO: Long alphanumeric tokens (review manually): {suspicious[:3]}')
    else:
        print('  PASS: no suspiciously long tokens')

print('\n=== FILE MANIFEST ===')
for f in sorted(base.rglob('*')):
    if f.is_file() and not any(p in str(f) for p in ['__pycache__', '.git']):
        rel = f.relative_to(base)
        print(f'  {rel}: {f.stat().st_size:,} bytes')

print('\n=== DONE ===')

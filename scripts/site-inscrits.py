#!/usr/bin/env python3
# Le vivier des inscrits du site, appelé par site-inscrits.sh : <psv> <dossier>.
import sys, csv, re
from datetime import datetime, timedelta
src, out = sys.argv[1], sys.argv[2]
# Domaines jetables : jamais créés (le 2026-10-28, 1 428 @mailinator.com avaient
# été importés actifs et nourris). L'import ne réactive jamais un contact
# existant, donc ne pas les écrire suffit.
# ponytail: liste à la main ; un paquet de domaines jetables si d'autres arrivent.
JETABLES = ('mailinator.com', 'yopmail.com', 'sharklasers.com', 'maildrop.cc',
            'dispostable.com', 'getnada.com')
# Ces familles changent de TLD (guerrillamail.net, 10minutemail.co.uk…) : le nom suffit.
FAMILLES = {'guerrillamail', '10minutemail', 'temp-mail', 'trashmail'}
def jetable(dom):
    return ('tempmail' in dom or any(dom == d or dom.endswith('.' + d) for d in JETABLES)
            or not FAMILLES.isdisjoint(dom.split('.')))
consumer = {'gmail.com','qq.com','163.com','126.com','yahoo.com','hotmail.com','outlook.com','icloud.com','proton.me','protonmail.com','live.com','yandex.ru','mail.ru','foxmail.com','gmx.de','web.de','me.com','aol.com','msn.com','hotmail.fr','yahoo.fr','orange.fr','free.fr','wanadoo.fr','laposte.net','sfr.fr'}
now = datetime.utcnow()
rows = {'quota':[], 'actif':[], 'dormant':[], 'payant':[]}
inactifs = []
for line in open(src, encoding='utf-8', errors='replace'):
    p = line.rstrip('\n').split('|')
    if len(p) == 2 and p[0] == 'inactif':
        inactifs.append(p[1].strip().lower()); continue
    if len(p) < 12: continue
    uid, email, name, company, plan, rm, rt, last_login, created, verified, stripe, chan = p[:12]
    email = email.strip().lower()
    if not re.match(r'^[^@\s]+@[^@\s]+\.[a-z]{2,}$', email) or email.endswith('@example.com'): continue
    dom = email.split('@')[1]
    if jetable(dom): continue
    first, last = (name.strip().split(' ',1)+[''])[:2] if name.strip() else ('','')
    comp = company.strip() or (dom if dom not in consumer else (name.strip() or email.split('@')[0]))
    try: ll = datetime.fromisoformat(last_login[:19]) if last_login else None
    except ValueError: ll = None
    rec = [email, first[:60], last[:60], comp[:120], '', ('https://'+dom) if dom not in consumer else '', '', '']
    if plan != 'free': rows['payant'].append(rec)
    elif int(rm or 0) >= 80: rows['quota'].append(rec)
    elif (ll and ll >= now - timedelta(days=30)) or int(rt or 0) >= 10: rows['actif'].append(rec)
    else: rows['dormant'].append(rec)
for k, v in rows.items():
    with open(f'{out}/site-{k}.csv','w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['email','first_name','last_name','company_name','phone_number','website','linkedin_profile','location']); w.writerows(v)
    print(f'{k} {len(v)}')
with open(f'{out}/site-inactifs.txt', 'w', encoding='utf-8') as f:
    f.write(''.join(m + '\n' for m in inactifs))
print(f'inactifs {len(inactifs)}')

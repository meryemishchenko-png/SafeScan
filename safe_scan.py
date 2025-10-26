#!/usr/bin/env python3
"""
SafeScan - Basit siber güvenlik dosya tarayıcı (TalentCup-2025)
Kullanım:
    python safe_scan.py --path /tarama/klasoru --quarantine ./karantina

Özellikler:
- Bilinen zararlı hash'leri kontrol eder (simülasyon örnekleri)
- Şüpheli dosya uzantılarını tarar (.exe, .js, .vbs, .bat vb.)
- Dosya içeriğinde şüpheli göstergeleri arar (eval, base64, powershell)
- Bulunan şüpheli dosyalar karantinaya taşınır
- JSON formatında rapor oluşturur
"""
import os, sys, argparse, hashlib, json, shutil, datetime, re

SIGNATURE_DB = {
    "d41d8cd98f00b204e9800998ecf8427e": "Ornek-Malware-Boş",
    "e2fc714c4727ee9395f324cd2e7f331f": "Ornek-Malware-Test",
}

SUSPICIOUS_EXT = {'.exe', '.js', '.vbs', '.bat'}
SUSPICIOUS_STRINGS = [r"eval\(", r"base64", r"powershell"]

def md5_hesapla(dosya, blok=65536):
    h = hashlib.md5()
    try:
        with open(dosya, 'rb') as f:
            for b in iter(lambda: f.read(blok), b''):
                h.update(b)
        return h.hexdigest()
    except:
        return None

def dosya_incele(yol):
    info = {"yol": yol, "boyut": None, "md5": None,
            "sifreli_hash": False, "supheli_ext": False,
            "supheli_icerik": False, "nedenler": []}
    try:
        info["boyut"] = os.path.getsize(yol)
    except:
        return info

    md5 = md5_hesapla(yol)
    info["md5"] = md5
    if md5 in SIGNATURE_DB:
        info["sifreli_hash"] = True
        info["nedenler"].append(f"Bilinen hash: {SIGNATURE_DB[md5]}")

    _, ext = os.path.splitext(yol.lower())
    if ext in SUSPICIOUS_EXT:
        info["supheli_ext"] = True
        info["nedenler"].append(f"Şüpheli uzantı: {ext}")

    try:
        with open(yol, 'rb') as f:
            data = f.read()
        text = data.decode('utf-8', errors='ignore').lower()
        for pattern in SUSPICIOUS_STRINGS:
            if re.search(pattern, text):
                info["supheli_icerik"] = True
                info["nedenler"].append(f"Şüpheli içerik: {pattern}")
    except:
        pass

    return info

def tara(yol, karantina=None, rapor="rapor.json", verbose=True):
    bulgular = []
    toplam = 0
    for dirpath, dirs, files in os.walk(yol):
        for fn in files:
            toplam += 1
            tam_yol = os.path.join(dirpath, fn)
            info = dosya_incele(tam_yol)
            if any([info["sifreli_hash"], info["supheli_ext"], info["supheli_icerik"]]):
                info["supheli"] = True
                bulgular.append(info)
                if karantina:
                    try:
                        os.makedirs(karantina, exist_ok=True)
                        dst = os.path.join(karantina, fn)
                        shutil.move(tam_yol, dst)
                        info["karantinaya_taşındı"] = dst
                        if verbose:
                            print(f"[KARANTİNA] {tam_yol} -> {dst}")
                    except Exception as e:
                        info["hata"] = str(e)
                        if verbose:
                            print(f"[HATA] {tam_yol}: {e}")
                elif verbose:
                    print(f"[ŞÜPHELİ] {tam_yol} Nedenler: {info['nedenler']}")
    rapor_veri = {
        "tarama_zamani": datetime.datetime.utcnow().isoformat() + "Z",
        "taranan_kok": yol,
        "toplam_tarandi": toplam,
        "bulunan_supheli": len(bulgular),
        "bulgular": bulgular
    }
    with open(rapor, 'w', encoding='utf-8') as f:
        json.dump(rapor_veri, f, ensure_ascii=False, indent=2)
    if verbose:
        print(f"[RAPOR] {rapor} kaydedildi.")
    return rapor_veri

def main():
    parser = argparse.ArgumentParser(description="SafeScan - Basit dosya tarayıcı")
    parser.add_argument('--path', '-p', required=True, help="Tarama yapılacak klasör")
    parser.add_argument('--quarantine', '-q', default=None, help="Karantina klasörü (opsiyonel)")
    parser.add_argument('--report', '-r', default="rapor.json", help="Rapor dosyası (json)")
    parser.add_argument('--verbose', '-v', action='store_true', help="Detaylı çıktı")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print("Hata: Tarama yolu bulunamadı:", args.path)
        sys.exit(1)

    print("SafeScan başlatılıyor...")
    print("Tarama dizini:", args.path)
    if args.quarantine:
        print("Karantina dizini:", args.quarantine)

    tara(args.path, karantina=args.quarantine, rapor=args.report, verbose=args.verbose)
    print("Tarama tamamlandı.")
    
if __name__ == "__main__":
    main()

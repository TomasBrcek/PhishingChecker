# PhishingChecker

PhishingChecker je nástroj na detekciu potenciálne phishingových URL. Umožňuje analyzovať URL adresy a generovať predikcie pravdepodobnosti phishingu pomocou modelu strojového učenia.

---

## Obsah

- [Funkcionalita](#funkcionalita)
- [Požiadavky](#požiadavky)
- [Inštalácia a spustenie](#inštalácia-a-spustenie)
  - [Lokálne (Python + virtuálne prostredie)](#lokálne-python--virtuálne-prostredie)
  - [Docker / Docker Compose](#docker--docker-compose)
- [Použitie](#použitie)
- [Disclaimer](#disclaimer)

---

## Funkcionalita

- Analýza URL a výpočet pravdepodobnosti, či ide o phishing.
- Interpretácia výsledkov na základe natrénovaného modelu.
- Jednoduché webové rozhranie.
- Možnosť spustenia cez Python alebo Docker.

---

## Požiadavky

### Lokálne spúšťanie

- **Python 3.7+**
- `pip` na správu balíkov
- Zoznam všetkých závislostí sa nachádza v `requirements.txt`

### Docker

- **Docker**
- **Docker Compose**

---

## Inštalácia a spustenie

### Lokálne (Python + virtuálne prostredie)

Návod je rovnaký pre Windows, macOS aj Linux:

#### 1. Klonuj repozitár

```bash
git clone git@github.com:TomasBrcek/PhishingChecker.git
cd PhishingChecker
```

#### 2. Vytvor virtuálne prostredie

##### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

##### Windows (PowerShell)

```bash
python -m venv venv
.\venv\Scripts\Activate.ps1
```

##### Windows (CMD)

```bash
python -m venv venv
.\venv\Scripts\activate.bat
```

#### 3. Nainštaluj závislosti

```bash
pip install -r requirements.txt
```

#### 4. Spusti aplikáciu

```bash
python main.py
```

### Docker / Docker Compose

1. Uisti sa, že si v koreňovom adresári projektu
2. Spusti aplikáciu cez Docker Compose:

```bash
docker-compose up --build
```

3. Po spustení bude aplikácia dostupná na porte 8000
4. Zastavenie:

```bash
docker-compose down
```

---

## Použitie

1. Spusti aplikáciu podľa jednej z vyššie uvedených metód.
2. Otvor webový prehliadač.
3. Prejdi do adresára **static/** a otvor súbor `index.html`.
4. Zadaj URL adresu, ktorú chceš analyzovať.
5. Klikni na tlačidlo "Verify" a počkaj na výsledky.
6. Výsledky budú zobrazené na stránke vrátane pravdepodobnosti phishingu a interpretácie.

---

## Disclaimer

- Tento nástroj slúži výhradne na vzdelávacie a výskumné účely.
- Predikcie modelu môžu byť nepresné. Neber ich ako jediný zdroj pravdy.
- Autor nezodpovedá za škody spôsobené nesprávnym použitím nástroja.
- Používanie tohto nástroja na škodlivé účely je prísne zakázané.

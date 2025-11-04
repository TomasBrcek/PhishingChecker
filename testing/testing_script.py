import argparse
from pathlib import Path
import random
import requests

ENDPOINT_DEFAULT = "http://0.0.0.0:8000/predict"

def load_urls(path, n):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {path}")
    with p.open("r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]
        random.shuffle(urls)
        return urls[:n]

def extract_prediction_and_prob(data):
    pred = None
    prob = None
    if isinstance(data, dict):
        if "prediction" in data:
            try:
                pred = int(data["prediction"]) if data["prediction"] is not None else None
            except Exception:
                pred = None
        for k in ("phishing_probability", "probability", "proba", "score"):
            if k in data and data[k] is not None:
                try:
                    prob = float(data[k])
                    break
                except Exception:
                    prob = None
    return pred, prob

def main():
    parser = argparse.ArgumentParser(description="Simple URL phishing checker.")
    parser.add_argument("--n", default=100, help="Number of URLs to process.")
    args = parser.parse_args()

    urls = load_urls("testing/testing_dataset.txt", int(args.n))

    if not urls:
        print("No URLs found in the input file.")
        return

    session = requests.Session()

    total = 0
    sum_predictions = 0
    counted_predictions = 0
    correct = 0
    true_positives = 0
    true_negatives = 0
    false_positives = 0
    false_negatives = 0

    for i, url in enumerate(urls, start=1):
        total += 1
        url, label = url.split(",") if "," in url else (url, None)
        label = int(label)
        payload = {"url": url}
        try:
            resp = session.post(ENDPOINT_DEFAULT, json=payload, timeout=1000, headers={"Content-Type":"application/json"})
            status = resp.status_code
            try:
                data = resp.json()
            except Exception:
                data = {"_raw": resp.text}
            pred, prob = extract_prediction_and_prob(data)
            if pred is not None:
                sum_predictions += pred
                counted_predictions += 1
                if label is not None:
                    if pred == label:
                        correct += 1
                        if pred == 1:
                            true_positives += 1
                        else:
                            true_negatives += 1
                    else:
                        if pred == 1:
                            false_positives += 1
                        else:
                            false_negatives += 1

            if pred is None and prob is None:
                print(f"[{correct}/{total}] {url} -> status={status}  (no prediction in response)")
            else:
                print_str = f"[{correct}/{total}] {url} -> prediction={pred}  probability={prob}  status={status}"
                print(print_str)
        except requests.RequestException as e:
            print(f"[{i}/{total}] {url} -> REQUEST ERROR: {e}")

    # final summary
    print("\n=== FINAL SUMMARY ===")
    print(f"Total URLs processed: {total}")

    evaluated = counted_predictions
    if evaluated > 0:
        accuracy = correct / evaluated
        print("--------------------------------------")
        print(f"True positives = {true_positives}")
        print(f"True negatives = {true_negatives}")
        print(f"False positives = {false_positives}")
        print(f"False negatives = {false_negatives}")
        print("--------------------------------------")
        print(f"Correct predictions = {correct}/{evaluated}  -> Accuracy = {accuracy:.4f}")

        if true_positives + false_negatives > 0:
            recall = true_positives / (true_positives + false_negatives)
            print(f"Recall = {recall:.4f}")
    else:
        print("No valid predictions to evaluate accuracy.")

if __name__ == "__main__":
    main()

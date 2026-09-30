import json
from pathlib import Path

from soc_automation.models import SecurityEvent
from soc_automation.pipeline import process_event


def load_dataset(path: str = "experiments/dataset.json") -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def evaluate(path: str = "experiments/dataset.json") -> dict:
    dataset = load_dataset(path)
    tp = fp = tn = fn = 0

    for item in dataset:
        event = SecurityEvent(
            event_id=item["event_id"],
            source=item["source"],
            event_type=item["event_type"],
            source_ip=item.get("source_ip"),
            username=item.get("username"),
            message=item["message"],
        )
        detected = process_event(event) is not None
        malicious = item["label"] == "malicious"

        if detected and malicious:
            tp += 1
        elif detected and not malicious:
            fp += 1
        elif not detected and malicious:
            fn += 1
        else:
            tn += 1

    total = len(dataset)
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return {
        "dataset_size": total,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))

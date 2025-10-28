# utils.py
import pandas as pd

def add_missing_flags(X):
    X = X.copy()
    for col in ["domain_age", "registration_length", "days_to_expire"]:
        X[f"{col}_missing"] = X[col].isna().astype(int)
    return X

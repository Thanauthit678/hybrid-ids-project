import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, accuracy_score, f1_score,
    precision_score, recall_score
)

from utils import apply_balanced_smote

# 1. ตั้งค่า Path
INPUT_PATH = "./output/selected_data.parquet"
MODEL_DIR = "./models"
OUTPUT_DIR = "./output"
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

MAX_TRAIN_FOR_GRIDSEARCH = 150_000  # จำกัดขนาดตอน Grid Search ให้รันจบได้ในเวลาที่เหมาะสม
MAX_TRAIN_FOR_FINAL_RF = 300_000
MAX_BENIGN_FOR_IF = 100_000

# พารามิเตอร์กริดตามตารางที่ 7 ในบทที่ 3
# (ลดขนาดกริดลงจากตารางเต็มเพื่อให้รันจบในเวลาที่เหมาะสมบนสเปกเครื่อง i5/Ryzen5, RAM 8GB
#  ตามที่ระบุไว้ในขอบเขตการทดลอง ถ้ามีเครื่องแรงกว่านี้ เพิ่มค่ากลับได้ เช่น
#  n_estimators: [100, 200, 300], max_depth: [10, 20, 30] ตามตารางเต็ม)
RF_PARAM_GRID = {
    'n_estimators': [100, 200],
    'max_depth': [10, 20],
    'min_samples_split': [2, 5],
    'min_samples_leaf': [1, 2],
    'max_features': ['sqrt'],
    'criterion': ['gini'],
}

# พารามิเตอร์ตามตารางที่ 8 สำหรับ Isolation Forest
IF_PARAM_GRID = [
    {'n_estimators': n, 'contamination': c}
    for n in [100, 200]
    for c in [0.01, 0.03, 0.05, 0.10]
]


def train_final_models():
    print("กำลังโหลดข้อมูล selected_data.parquet...")
    df = pd.read_parquet(INPUT_PATH)

    X = df.drop(columns=['Label'])
    y = df['Label']

    # -----------------------------------------------------------------
    # แบ่งข้อมูลแบบ 3 ส่วน: Train / Validation / Test
    #   - Test (20% ของทั้งหมด)      : ใช้รายงานผลสุดท้ายในบทที่ 4 เท่านั้น ห้ามใช้ตอนปรับพารามิเตอร์
    #   - Validation (16% ของทั้งหมด): ใช้เลือกพารามิเตอร์ของ Isolation Forest (ตารางที่ 8)
    #   - Train (64% ของทั้งหมด)     : ใช้ฝึกโมเดลจริง + Grid Search ของ Random Forest
    # -----------------------------------------------------------------
    X_trainval, X_test, y_trainval, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_trainval, y_trainval, test_size=0.2, random_state=42, stratify=y_trainval
    )
    print(f"ขนาด Train: {len(X_train):,} | Validation: {len(X_val):,} | Test: {len(X_test):,}")

    # -----------------------------------------------------------------
    # Data Transformation: StandardScaler (fit บน Train เท่านั้น)
    # -----------------------------------------------------------------
    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=X_train.columns, index=X_train.index)
    X_val_scaled = pd.DataFrame(scaler.transform(X_val), columns=X_val.columns, index=X_val.index)
    X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=X_test.columns, index=X_test.index)

    # ตัดข้อมูล Train ให้อยู่ในขนาดที่ Grid Search ได้ทันเวลา
    if len(X_train_scaled) > MAX_TRAIN_FOR_GRIDSEARCH:
        X_train_gs, _, y_train_gs, _ = train_test_split(
            X_train_scaled, y_train, train_size=MAX_TRAIN_FOR_GRIDSEARCH, random_state=42, stratify=y_train
        )
    else:
        X_train_gs, y_train_gs = X_train_scaled, y_train

    # Imbalanced Data Handling: SMOTE (เฉพาะชุดที่ใช้ฝึกเท่านั้น)
    X_train_bal, y_train_bal = apply_balanced_smote(
        X_train_gs, y_train_gs, cap_ratio=0.3, min_target=3000, random_state=42
    )

    # ===================================================================
    # 1) Random Forest: Grid Search + Cross Validation (ตารางที่ 7)
    # ===================================================================
    print("\nกำลังทำ Grid Search สำหรับ Random Forest (อาจใช้เวลาสักครู่)...")
    grid_search = GridSearchCV(
        estimator=RandomForestClassifier(random_state=42, n_jobs=-1, class_weight='balanced'),
        param_grid=RF_PARAM_GRID,
        scoring='f1_macro',
        cv=3,
        n_jobs=-1,
        verbose=1,
    )
    grid_search.fit(X_train_bal, y_train_bal)

    print(f"[OK] พารามิเตอร์ที่ดีที่สุดของ Random Forest: {grid_search.best_params_}")
    print(f"[OK] F1-macro (Cross Validation): {grid_search.best_score_:.4f}")

    pd.DataFrame(grid_search.cv_results_).to_csv(
        os.path.join(OUTPUT_DIR, "rf_gridsearch_results.csv"), index=False
    )
    with open(os.path.join(OUTPUT_DIR, "rf_best_params.json"), 'w', encoding='utf-8') as f:
        json.dump(grid_search.best_params_, f, indent=2, ensure_ascii=False)

    rf_model = grid_search.best_estimator_

    # ---- ฝึกซ้ำด้วยข้อมูล Train เต็มขนาด (สูงสุด MAX_TRAIN_FOR_FINAL_RF) ด้วยพารามิเตอร์ที่ดีที่สุด ----
    if len(X_train_scaled) > MAX_TRAIN_FOR_FINAL_RF:
        X_train_final, _, y_train_final, _ = train_test_split(
            X_train_scaled, y_train, train_size=MAX_TRAIN_FOR_FINAL_RF, random_state=42, stratify=y_train
        )
    else:
        X_train_final, y_train_final = X_train_scaled, y_train

    X_train_final_bal, y_train_final_bal = apply_balanced_smote(
        X_train_final, y_train_final, cap_ratio=0.3, min_target=3000, random_state=42
    )

    rf_model.fit(X_train_final_bal, y_train_final_bal)

    # ---- ประเมินผล Random Forest บน Test Set (ห้ามแตะจนถึงจุดนี้) ----
    rf_preds = rf_model.predict(X_test_scaled)
    print("\n--- ผลการประเมิน Random Forest Model (บน Test Set) ---")
    print(f"Accuracy : {accuracy_score(y_test, rf_preds):.4f}")
    print(f"Precision: {precision_score(y_test, rf_preds, average='macro', zero_division=0):.4f}")
    print(f"Recall   : {recall_score(y_test, rf_preds, average='macro'):.4f}")
    print(f"F1-Score : {f1_score(y_test, rf_preds, average='macro'):.4f}")
    print("\n" + classification_report(y_test, rf_preds, zero_division=0))

    # ===================================================================
    # 2) Isolation Forest: ค้นหาพารามิเตอร์ด้วย Validation Set (ตารางที่ 8)
    # Isolation Forest เป็น Unsupervised จึงใช้ GridSearchCV ปกติไม่ได้ตรงๆ
    # (ไม่มี Label ตอนฝึก) จึงประเมินคุณภาพจาก Validation Set ที่มี Label จริงแทน
    # ตามที่ระบุไว้ในบทที่ 3
    # ===================================================================
    print("\nกำลังค้นหาพารามิเตอร์ที่เหมาะสมของ Isolation Forest ด้วย Validation Set...")

    X_benign_train = X_train_final_bal[y_train_final_bal == 'BENIGN']
    if len(X_benign_train) > MAX_BENIGN_FOR_IF:
        X_benign_train = X_benign_train.sample(n=MAX_BENIGN_FOR_IF, random_state=42)

    y_val_binary = (y_val != 'BENIGN').astype(int)  # 1 = attack, 0 = benign

    if_search_results = []
    best_if_score, best_if_params = -1, None

    for params in IF_PARAM_GRID:
        iso_temp = IsolationForest(max_samples='auto', max_features=1.0,
                                    random_state=42, n_jobs=-1, **params)
        iso_temp.fit(X_benign_train)
        val_preds = iso_temp.predict(X_val_scaled)
        val_preds_binary = (val_preds == -1).astype(int)

        f1 = f1_score(y_val_binary, val_preds_binary)
        recall = recall_score(y_val_binary, val_preds_binary)
        precision = precision_score(y_val_binary, val_preds_binary, zero_division=0)

        if_search_results.append({**params, 'f1': f1, 'recall': recall, 'precision': precision})
        print(f"   n_estimators={params['n_estimators']:<4} contamination={params['contamination']:<5} "
              f"-> F1={f1:.4f} Recall={recall:.4f} Precision={precision:.4f}")

        if f1 > best_if_score:
            best_if_score, best_if_params = f1, params

    print(f"\n[OK] พารามิเตอร์ที่ดีที่สุดของ Isolation Forest: {best_if_params} (F1={best_if_score:.4f})")

    pd.DataFrame(if_search_results).to_csv(
        os.path.join(OUTPUT_DIR, "if_gridsearch_results.csv"), index=False
    )
    with open(os.path.join(OUTPUT_DIR, "if_best_params.json"), 'w', encoding='utf-8') as f:
        json.dump(best_if_params, f, indent=2, ensure_ascii=False)

    iso_model = IsolationForest(max_samples='auto', max_features=1.0,
                                 random_state=42, n_jobs=-1, **best_if_params)
    iso_model.fit(X_benign_train)

    # ===================================================================
    # 3) ประเมินเปรียบเทียบ 3 วิธี: Random Forest, Isolation Forest, Hybrid Detection
    #    (ตอบโจทย์ขอบเขตงานวิจัยข้อ 4 ที่ระบุไว้ว่า "เปรียบเทียบผลลัพธ์ระหว่าง Random
    #     Forest, Isolation Forest และ Hybrid Detection" ครบทั้ง 3 วิธี ไม่ใช่แค่ 2 วิธี)
    # ===================================================================
    print("\n--- เปรียบเทียบ RF อย่างเดียว vs IF อย่างเดียว vs Hybrid Detection (บน Test Set) ---")
    y_test_binary = (y_test != 'BENIGN').astype(int)
    rf_preds_binary = (rf_preds != 'BENIGN').astype(int)

    # 3.1) Isolation Forest อย่างเดียว: รันกับ Test Set ทั้งชุด (ไม่ผ่าน RF ก่อน)
    if_only_preds = iso_model.predict(X_test_scaled)
    if_only_preds_binary = (if_only_preds == -1).astype(int)

    # 3.2) Hybrid (RF ก่อน แล้วส่งต่อเฉพาะที่ RF ทายว่า BENIGN ไปให้ IF ตรวจซ้ำ)
    passed_to_if_mask = (rf_preds == 'BENIGN')
    hybrid_preds_binary = rf_preds_binary.copy()
    if passed_to_if_mask.sum() > 0:
        if_preds = iso_model.predict(X_test_scaled[passed_to_if_mask])
        hybrid_preds_binary[passed_to_if_mask] = (if_preds == -1).astype(int)

    methods = {
        'Random Forest only': rf_preds_binary,
        'Isolation Forest only': if_only_preds_binary,
        'Hybrid (RF + Isolation Forest)': hybrid_preds_binary,
    }

    comparison_rows = []
    for name, preds_binary in methods.items():
        precision = precision_score(y_test_binary, preds_binary, zero_division=0)
        recall = recall_score(y_test_binary, preds_binary)
        f1 = f1_score(y_test_binary, preds_binary)
        print(f"{name:<32}: Precision={precision:.4f}  Recall={recall:.4f}  F1={f1:.4f}")
        comparison_rows.append({
            'Method': name, 'Precision': precision, 'Recall': recall, 'F1': f1
        })

    comparison_df = pd.DataFrame(comparison_rows)
    comparison_path = os.path.join(OUTPUT_DIR, "rf_vs_hybrid_comparison.csv")
    comparison_df.to_csv(comparison_path, index=False)
    print(f"\n[OK] บันทึกผลเปรียบเทียบ RF vs IF vs Hybrid ไว้ที่: {comparison_path}")

    # ===================================================================
    # 4) บันทึกโมเดลและ scaler ทั้งหมด
    #    (สำคัญ: ต้องใช้ scaler ตัวเดียวกันนี้ตอน Online Detection ใน hybrid_engine.py ด้วย!)
    # ===================================================================
    joblib.dump(rf_model, os.path.join(MODEL_DIR, "random_forest_model.pkl"))
    joblib.dump(iso_model, os.path.join(MODEL_DIR, "isolation_forest_model.pkl"))
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))

    with open(os.path.join(MODEL_DIR, "feature_order.json"), 'w', encoding='utf-8') as f:
        json.dump(list(X.columns), f, indent=2, ensure_ascii=False)

    print(f"\n[OK] บันทึกโมเดล Random Forest, Isolation Forest และ Scaler ไว้ที่: {MODEL_DIR}")
    print("[สำคัญ] hybrid_engine.py ต้องโหลด scaler.pkl มา transform ข้อมูลก่อนส่งเข้า "
          "rf_model.predict()/iso_model.predict() ด้วย ไม่งั้นผลจะไม่ตรงกับตอนฝึก")


if __name__ == '__main__':
    train_final_models()
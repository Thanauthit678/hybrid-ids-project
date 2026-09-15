import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, f1_score

from utils import apply_balanced_smote, safe_train_test_split

# 1. ตั้งค่า Path
INPUT_PATH = "./output/selected_data.parquet"
OUTPUT_DIR = "./output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

MAX_TRAIN_SAMPLES = 100_000   # จำกัดขนาด Train ต่อรอบ LOAO เพื่อความเร็ว (ตามสเปกเครื่อง i5/Ryzen5, RAM 8GB)
MAX_BENIGN_FOR_IF = 50_000
IF_CONTAMINATION = 0.03       # ถ้ารัน 05_train_final_model.py แล้ว แนะนำใช้ค่าจาก if_best_params.json แทน


def run_loao_evaluation():
    print("กำลังโหลดข้อมูล selected_data.parquet...")
    df = pd.read_parquet(INPUT_PATH)

    # ครอบคลุมตามขอบเขตงานวิจัยข้อ 1.4 ที่ระบุไว้ว่า "DDoS, Brute Force, Port Scan
    # Botnet, DoS, Heartbleed และ Web Attack" -> เพิ่ม 'Bot' (Botnet) และ 'Heartbleed'
    # เข้ามาด้วย (Heartbleed มีแค่ ~11 samples ทั้งชุดข้อมูล ผลจะมีความแปรปรวนสูงเพราะ
    # ตัวอย่างทดสอบน้อยมาก แต่ยังจำเป็นต้องรายงานไว้เพื่อให้ครบตามขอบเขปที่วางไว้)
    attack_types = [
        'DDoS', 'PortScan', 'DoS Hulk', 'FTP-Patator',
        'DoS slowloris', 'DoS Slowhttptest', 'SSH-Patator', 'Web Attack',
        'Bot', 'Heartbleed'
    ]
    # ใช้เฉพาะ attack type ที่มีอยู่จริงในข้อมูล กันกรณีชื่อคลาสไม่ตรงหรือถูกกรองออกไปแล้ว
    available_labels = set(df['Label'].unique())
    attack_types = [a for a in attack_types if a in available_labels]

    loao_results = []

    print("\n" + "=" * 60)
    print(" เริ่มการประเมินแบบ Leave-One-Attack-Out (LOAO) ")
    print("=" * 60)

    for holdout_attack in attack_types:
        print(f"\n[LOAO Loop] ตัดการโจมตีประเภท: '{holdout_attack}' ออกให้เป็น Unknown Attack")

        # 1. แยก Dataset เป็น Known (สำหรับ Train/Test โมเดล) และ Unknown (ใช้ Test เท่านั้น)
        known_df = df[df['Label'] != holdout_attack].copy()
        unknown_df = df[df['Label'] == holdout_attack].copy()

        if len(unknown_df) == 0:
            continue

        X_known = known_df.drop(columns=['Label'])
        y_known = known_df['Label']

        # 2. แบ่ง Known Data เป็น Train (80%) และ Test (20%)
        #    ใช้ safe_train_test_split เพราะเมื่อรวม Heartbleed เข้ามา (~11 samples ทั้งชุด)
        #    การ stratify ปกติอาจ error ถ้าคลาสเล็กเกินไป
        X_train, X_test, y_train, y_test = safe_train_test_split(
            X_known, y_known, test_size=0.2, random_state=42
        )

        # 3. สุ่ม Sample Data สำหรับการฝึก (dataset ใหญ่มาก จำกัดขนาดเพื่อความเร็ว)
        if len(X_train) > MAX_TRAIN_SAMPLES:
            try:
                X_train_sub, _, y_train_sub, _ = train_test_split(
                    X_train, y_train, train_size=MAX_TRAIN_SAMPLES, random_state=42, stratify=y_train
                )
            except ValueError as e:
                print(f"   [WARNING] stratify ตอนสุ่มลดขนาด Train ล้มเหลว ({e}) -> สุ่มแบบไม่ stratify แทน")
                X_train_sub, _, y_train_sub, _ = train_test_split(
                    X_train, y_train, train_size=MAX_TRAIN_SAMPLES, random_state=42
                )
        else:
            X_train_sub, y_train_sub = X_train, y_train

        # 4. Data Transformation: StandardScaler (fit บน Train เท่านั้น ป้องกัน Data Leakage)
        scaler = StandardScaler()
        X_train_scaled = pd.DataFrame(
            scaler.fit_transform(X_train_sub), columns=X_train_sub.columns, index=X_train_sub.index
        )
        X_test_scaled = pd.DataFrame(
            scaler.transform(X_test), columns=X_test.columns, index=X_test.index
        )
        X_unknown_scaled = pd.DataFrame(
            scaler.transform(unknown_df.drop(columns=['Label'])),
            columns=X_train_sub.columns, index=unknown_df.index
        )

        # 5. Imbalanced Data Handling: SMOTE (เฉพาะชุด Train เท่านั้น)
        X_train_bal, y_train_bal = apply_balanced_smote(
            X_train_scaled, y_train_sub, cap_ratio=0.3, min_target=3000, random_state=42
        )

        # 6. ฝึก Random Forest (Supervised - Known Attack Detection)
        rf = RandomForestClassifier(
            n_estimators=100, max_depth=20, random_state=42, n_jobs=-1,
            class_weight='balanced'
        )
        rf.fit(X_train_bal, y_train_bal)

        # รายงานผล RF บน Known Test Set ประกอบบทที่ 4
        rf_test_preds = rf.predict(X_test_scaled)
        test_accuracy = accuracy_score(y_test, rf_test_preds)
        test_f1_macro = f1_score(y_test, rf_test_preds, average='macro')
        print(f"   --- ผล Random Forest บน Known Test Set: Accuracy={test_accuracy:.4f}  "
              f"F1(macro)={test_f1_macro:.4f}")

        # 7. ฝึก Isolation Forest (Unsupervised - Anomaly Detection) ด้วยข้อมูล BENIGN เท่านั้น
        X_benign_train = X_train_bal[y_train_bal == 'BENIGN']
        if len(X_benign_train) > MAX_BENIGN_FOR_IF:
            X_benign_train = X_benign_train.sample(n=MAX_BENIGN_FOR_IF, random_state=42)

        iso_forest = IsolationForest(
            n_estimators=100, contamination=IF_CONTAMINATION, random_state=42, n_jobs=-1
        )
        iso_forest.fit(X_benign_train)

        # 8. ทดสอบ Hybrid Detection บน Unknown Attack (Holdout Attack)
        rf_preds = rf.predict(X_unknown_scaled)

        # ข้อมูลที่ RF ทายว่าไม่ใช่ BENIGN นับว่าถูกจับได้ (ไม่ว่าจะทายเป็น attack ชนิดใดก็ตาม)
        # ข้อมูลที่ RF ทายว่าเป็น BENIGN จะหลุดไปยัง Isolation Forest
        passed_to_if_mask = (rf_preds == 'BENIGN')
        X_passed_to_if = X_unknown_scaled[passed_to_if_mask]

        if len(X_passed_to_if) > 0:
            if_preds = iso_forest.predict(X_passed_to_if)  # -1 = Anomaly, 1 = Normal
            if_detected_cnt = int(np.sum(if_preds == -1))
        else:
            if_detected_cnt = 0

        rf_detected_cnt = int(np.sum(~passed_to_if_mask))
        total_detected = rf_detected_cnt + if_detected_cnt
        total_unknown_samples = len(X_unknown_scaled)
        detection_rate = (total_detected / total_unknown_samples) * 100

        print(f"   -> จำนวนตัวอย่าง Unknown ทั้งหมด: {total_unknown_samples:,}")
        print(f"   -> RF ตรวจจับได้: {rf_detected_cnt:,}")
        print(f"   -> Isolation Forest ตรวจจับเพิ่มได้: {if_detected_cnt:,}")
        print(f"   => Unknown Attack Detection Rate: {detection_rate:.2f}%")

        loao_results.append({
            'Holdout_Attack': holdout_attack,
            'Total_Samples': total_unknown_samples,
            'RF_Detected': rf_detected_cnt,
            'IF_Detected': if_detected_cnt,
            'Total_Detected': total_detected,
            'Detection_Rate_Pct': round(detection_rate, 2),
            'Known_Test_Accuracy': round(test_accuracy, 4),
            'Known_Test_F1_Macro': round(test_f1_macro, 4),
        })

    # บันทึกผลลัพธ์ LOAO
    results_df = pd.DataFrame(loao_results)
    print("\n" + "=" * 60)
    print(" สรุปผลการประเมิน Leave-One-Attack-Out (LOAO) ")
    print("=" * 60)
    print(results_df.to_string(index=False))

    avg_detection_rate = results_df['Detection_Rate_Pct'].mean()
    print(f"\n[RESULT] ค่าเฉลี่ย Unknown Attack Detection Rate รวม: {avg_detection_rate:.2f}%")

    results_path = os.path.join(OUTPUT_DIR, "loao_evaluation_results.csv")
    results_df.to_csv(results_path, index=False)
    print(f"[OK] บันทึกผลการประเมินเรียบร้อยที่: {results_path}")


if __name__ == '__main__':
    run_loao_evaluation()

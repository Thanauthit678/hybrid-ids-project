import os
import pandas as pd
import numpy as np
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# 1. ตั้งค่า Path
INPUT_PATH = "./output/cleaned_data.parquet"
OUTPUT_DIR = "./output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

TOP_N_FEATURES = 20
LEAKAGE_PURITY_THRESHOLD = 0.90  # ถ้า top port ของ label ใดครองสัดส่วน >= 90% ถือว่าเสี่ยง leakage สูง


def safe_stratified_sample(X, y, sample_frac=0.2, random_state=42):
    """
    สุ่มตัวอย่างแบบ stratify แต่กันปัญหาคลาสที่มีตัวอย่างน้อยเกินไป
    (เช่น Heartbleed ใน CICIDS2017 มีแค่ ~11 samples) ซึ่งจะทำให้
    train_test_split(stratify=...) โยน ValueError ถ้าคลาสใดเหลือตัวอย่าง
    ในผลลัพธ์น้อยกว่า 2
    """
    counts = y.value_counts()
    too_small = counts[counts < 2]
    if len(too_small) > 0:
        print(f"[WARNING] พบคลาสที่มีตัวอย่างน้อยกว่า 2 รายการ: {too_small.to_dict()} "
              f"-> จะสุ่มตัวอย่างแบบไม่ stratify แทน")
        X_sample, _, y_sample, _ = train_test_split(
            X, y, test_size=1 - sample_frac, random_state=random_state
        )
        return X_sample, y_sample

    try:
        X_sample, _, y_sample, _ = train_test_split(
            X, y, test_size=1 - sample_frac, random_state=random_state, stratify=y
        )
        return X_sample, y_sample
    except ValueError as e:
        print(f"[WARNING] stratify ล้มเหลว ({e}) -> ใช้การสุ่มแบบไม่ stratify แทน")
        X_sample, _, y_sample, _ = train_test_split(
            X, y, test_size=1 - sample_frac, random_state=random_state
        )
        return X_sample, y_sample


def analyze_destination_port_leakage(df, report_path):
    """
    วิเคราะห์ Feature Leakage ของ Destination Port ตามที่ระบุไว้ในบทที่ 2-3:
    ตรวจสอบว่าพอร์ตปลายทางมีความสัมพันธ์ตรงเกินไปกับประเภทการโจมตีหรือไม่
    (เช่น ถ้าเกือบทุกแถวของ 'DoS Hulk' ใช้ Destination Port เดียวกัน แปลว่าโมเดลอาจ
    เรียนรู้ทางลัดจากพอร์ตแทนที่จะเรียนรู้จากพฤติกรรมทราฟฟิกจริง)

    คืนค่า: bool ว่าควรตัด Destination Port ออกหรือไม่ (True = แนะนำให้ตัดออก)
    """
    lines = ["=" * 70, "Destination Port - Feature Leakage Analysis", "=" * 70]

    if 'Destination Port' not in df.columns:
        lines.append("ไม่พบคอลัมน์ 'Destination Port' ในชุดข้อมูล ข้ามการวิเคราะห์นี้")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
        return False

    suspicious_labels = []
    for label, group in df.groupby('Label'):
        top_port = group['Destination Port'].value_counts(normalize=True)
        if len(top_port) == 0:
            continue
        top_port_name = top_port.index[0]
        top_port_ratio = top_port.iloc[0]
        lines.append(f"  Label = {label:<25} จำนวน = {len(group):>10,}  "
                     f"Top Port = {top_port_name:<8}  สัดส่วน = {top_port_ratio:.3f}")
        if top_port_ratio >= LEAKAGE_PURITY_THRESHOLD and label != 'BENIGN':
            suspicious_labels.append((label, top_port_name, top_port_ratio))

    lines.append("")
    if suspicious_labels:
        lines.append(f"[พบความเสี่ยง] {len(suspicious_labels)} คลาสมีสัดส่วน Top Port สูงกว่า "
                     f"{LEAKAGE_PURITY_THRESHOLD:.0%} ซึ่งเสี่ยงต่อ Feature Leakage:")
        for label, port, ratio in suspicious_labels:
            lines.append(f"    - {label}: พอร์ต {port} ครองสัดส่วน {ratio:.1%}")
        recommend_drop = True
    else:
        lines.append("[ไม่พบความเสี่ยงชัดเจน] ไม่มีคลาสใดที่ Destination Port กระจุกตัวเกินเกณฑ์")
        recommend_drop = False

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))

    print("\n".join(lines))
    return recommend_drop


def select_features():
    print("กำลังโหลดข้อมูล cleaned_data.parquet...")
    df = pd.read_parquet(INPUT_PATH)

    # -----------------------------------------------------------------
    # ขั้นที่ 1: วิเคราะห์ Feature Leakage ของ Destination Port ก่อนตัดสินใจ
    # (ตามที่ระบุไว้ในบทที่ 2-3 ว่าต้องตรวจสอบอย่างละเอียด ไม่ตัดหรือเก็บไว้ทันที
    #  เพียงเพราะมีค่า Feature Importance สูง)
    # -----------------------------------------------------------------
    leakage_report_path = os.path.join(OUTPUT_DIR, "destination_port_leakage_report.txt")
    drop_dest_port = analyze_destination_port_leakage(df, leakage_report_path)

    X = df.drop(columns=['Label'])
    y = df['Label']

    if drop_dest_port and 'Destination Port' in X.columns:
        print("[DECISION] ตัด 'Destination Port' ออกจากชุด Feature เนื่องจากมีความเสี่ยง Feature Leakage สูง")
        X = X.drop(columns=['Destination Port'])
    else:
        print("[DECISION] คงคอลัมน์ 'Destination Port' ไว้ในชุด Feature (ไม่พบความเสี่ยง Leakage ชัดเจน)")

    print(f"จำนวน Feature ทั้งหมดก่อนคัดเลือก: {X.shape[1]}")

    # -----------------------------------------------------------------
    # ขั้นที่ 2: สุ่มตัวอย่างข้อมูล (แบบกันปัญหาคลาสตัวอย่างน้อย) เพื่อคำนวณ Feature Importance
    # -----------------------------------------------------------------
    print("กำลังสุ่มตัวอย่างข้อมูลเพื่อคำนวณ Feature Importance...")
    X_sample, y_sample = safe_stratified_sample(X, y, sample_frac=0.2, random_state=42)

    # -----------------------------------------------------------------
    # ขั้นที่ 3: เทรน Random Forest เบื้องต้น
    # ใส่ class_weight='balanced' เพื่อลดผลกระทบจากข้อมูลไม่สมดุลตอนคำนวณ Feature Importance
    # (ยังไม่ใช้ SMOTE ในขั้นนี้ เพราะเป็นแค่การประเมิน Importance เบื้องต้น ไม่ใช่โมเดลสุดท้าย)
    # -----------------------------------------------------------------
    print("กำลังฝึก Random Forest เพื่อคำนวณ Feature Importance...")
    rf = RandomForestClassifier(
        n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced'
    )
    rf.fit(X_sample, y_sample)

    importances = rf.feature_importances_
    feature_importance_df = pd.DataFrame({
        'Feature': X.columns,
        'Importance': importances
    }).sort_values(by='Importance', ascending=False).reset_index(drop=True)

    print("\n--- Top 20 Important Features ---")
    print(feature_importance_df.head(TOP_N_FEATURES).to_string(index=False))

    if 'Destination Port' in feature_importance_df['Feature'].values:
        rank = int(feature_importance_df.index[
            feature_importance_df['Feature'] == 'Destination Port'
        ][0]) + 1
        print(f"[INFO] Destination Port อยู่อันดับ Feature Importance ที่ {rank}")

    feature_importance_df.to_csv(
        os.path.join(OUTPUT_DIR, "feature_importance_full.csv"), index=False
    )

    # 5. คัดเลือก Features ตามเกณฑ์ (Top 20)
    top_features = feature_importance_df.head(TOP_N_FEATURES)['Feature'].tolist()

    # บันทึกรายชื่อ Feature ที่เลือกเป็นไฟล์ JSON (คงรูปแบบเดิม = list เฉยๆ เพื่อไม่กระทบ
    # โค้ดส่วนอื่นที่อาจอ่านไฟล์นี้อยู่แล้ว เช่น hybrid_engine.py)
    feature_list_path = os.path.join(OUTPUT_DIR, "selected_features.json")
    with open(feature_list_path, 'w', encoding='utf-8') as f:
        json.dump(top_features, f, indent=4, ensure_ascii=False)

    # บันทึกข้อมูลเมตาประกอบการตัดสินใจแยกไว้อีกไฟล์ (สำหรับอ้างอิงในบทที่ 4)
    meta_path = os.path.join(OUTPUT_DIR, "feature_selection_meta.json")
    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump({
            "selected_features": top_features,
            "destination_port_dropped": bool(drop_dest_port),
            "leakage_purity_threshold": LEAKAGE_PURITY_THRESHOLD,
        }, f, indent=4, ensure_ascii=False)

    # บันทึกข้อมูลเฉพาะ Features ที่คัดเลือกแล้ว
    selected_df = df[top_features + ['Label']]
    output_path = os.path.join(OUTPUT_DIR, "selected_data.parquet")
    selected_df.to_parquet(output_path, index=False)

    print(f"\n[OK] คัดเลือก {len(top_features)} Features สำเร็จ!")
    print(f"[OK] บันทึกรายชื่อ Feature ไว้ที่: {feature_list_path}")
    print(f"[OK] บันทึกข้อมูลเมตาการตัดสินใจไว้ที่: {meta_path}")
    print(f"[OK] บันทึก Dataset ที่คัดเลือกแล้วไว้ที่: {output_path}")
    print(f"[OK] บันทึกรายงานวิเคราะห์ Destination Port ไว้ที่: {leakage_report_path}")


if __name__ == '__main__':
    select_features()

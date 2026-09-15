import os
import pandas as pd
import numpy as np

# 1. ตั้งค่า Path
INPUT_PATH = "./output/merged_raw.parquet"
OUTPUT_DIR = "./output"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def preprocess_data():
    print("กำลังโหลดข้อมูลจาก merged_raw.parquet ...")
    df = pd.read_parquet(INPUT_PATH)
    print(f"ขนาดข้อมูลเริ่มต้น: {df.shape}")

    # 2. แก้ไขข้อความในคอลัมน์ Label ให้เป็นระเบียบ (แก้ปัญหาอักขระแปลกๆ)
    print("กำลังทำความสะอาดชื่อ Label...")
    df['Label'] = df['Label'].astype(str).str.replace('ï¿%', '–', regex=False)
    df['Label'] = df['Label'].str.replace('ï¿½', '–', regex=False)
    # รวม Web Attack ย่อยให้อยู่ในกลุ่มเดียวกันเพื่อความสะอาดของคลาส
    df['Label'] = df['Label'].apply(lambda x: 'Web Attack' if 'Web Attack' in x else x)

    # 3. จัดการ Missing Values และ Infinite Values
    print("กำลังจัดการค่า Missing และ Infinite...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # 4. ลบข้อมูลที่ซ้ำกัน (Duplicate Rows)
    print("กำลังลบข้อมูลที่ซ้ำกัน...")
    df.drop_duplicates(inplace=True)

    # 5. วิเคราะห์และตัด Feature Leakage / คอลัมน์ที่ไม่จำเป็นออก
    # ---------------------------------------------------------------
    # ตัดคอลัมน์ที่เป็นตัวระบุตัวตน (identifier) ออก เพราะไม่ใช่พฤติกรรมทราฟฟิกจริง
    # และเสี่ยงต่อ Feature Leakage (โมเดลอาจจำ IP/พอร์ตต้นทางแทนที่จะเรียนรู้พฤติกรรม)
    # หมายเหตุ: เพิ่ม 'Destination IP' เข้ามาด้วย (เดิมตัดแค่ Source IP ฝั่งเดียว
    # ซึ่งไม่สมมาตรและยังเสี่ยง leakage เท่ากัน)
    #
    # ส่วน 'Destination Port' ไม่ตัดในขั้นตอนนี้ เพราะต้องผ่านการวิเคราะห์อย่างละเอียด
    # ก่อนตัดสินใจ (ดู 03_feature_selection.py -> analyze_destination_port_leakage)
    # ---------------------------------------------------------------
    print("กำลังจัดการ Feature Leakage (ตัดคอลัมน์ identifier)...")
    drop_cols = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Source Port', 'source_file']
    df.drop(columns=[col for col in drop_cols if col in df.columns], inplace=True)

    print(f"ขนาดข้อมูลหลังทำความสะอาด: {df.shape}")
    print("\nสรุปจำนวน Class ล่าสุด:")
    print(df['Label'].value_counts())

    # หมายเหตุ: ขั้นตอน StandardScaler และ SMOTE/Class Weighting (การจัดการ Imbalanced Data)
    # ไม่ได้ทำในไฟล์นี้ เพราะทั้งสองอย่างต้อง fit บนชุด Train เท่านั้น (หลังแบ่ง Train/Test แล้ว)
    # เพื่อป้องกัน Data Leakage เข้าไปปนกับ Test Set ดูการใช้งานจริงได้ใน
    # 04_loao_evaluation.py และ 05_train_final_model.py (ใช้ StandardScaler + apply_balanced_smote
    # จาก utils.py)

    # 6. บันทึกข้อมูลที่คลีนแล้วเป็น cleaned_data.parquet
    output_path = os.path.join(OUTPUT_DIR, "cleaned_data.parquet")
    df.to_parquet(output_path, index=False)
    print(f"\n[OK] บันทึกข้อมูลที่ทำความสะอาดเรียบร้อยแล้วไว้ที่: {output_path}")


if __name__ == '__main__':
    preprocess_data()

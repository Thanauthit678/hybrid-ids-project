"""
01_load_and_eda.py
===================
ขั้นตอนที่ 1: โหลดชุดข้อมูล CICIDS2017 (8 ไฟล์แยกตามวัน) และสำรวจข้อมูลเบื้องต้น (EDA)

โครงงาน: Hybrid Network Intrusion Detection Using Random Forest and Isolation Forest

วิธีใช้งาน:
    1. แก้ไข DATA_DIR ให้ชี้ไปยังโฟลเดอร์ที่เก็บไฟล์ CSV ทั้ง 8 ไฟล์
    2. รันสคริปต์นี้: python 01_load_and_eda.py
    3. ผลลัพธ์จะถูกบันทึกเป็น:
        - merged_raw.parquet   (ข้อมูลรวมทั้งหมด สำหรับใช้ในขั้นตอนถัดไป)
        - eda_report.txt       (สรุปผลการสำรวจข้อมูล)
"""

import os
import glob
import pandas as pd
import numpy as np

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 200)

# ---------------------------------------------------------------------------
# 1) ตั้งค่า path
# ---------------------------------------------------------------------------
DATA_DIR = "./data/CICIDS2017"          # <-- แก้ตรงนี้ให้ตรงกับเครื่องของคุณ
OUTPUT_DIR = "./output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ชื่อไฟล์มาตรฐานของ CICIDS2017 (MachineLearningCSV version)
# ถ้าชื่อไฟล์ในเครื่องคุณไม่ตรงกับนี้ ใช้ glob("*.csv") แทนได้เลย (ดูด้านล่าง)
EXPECTED_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]


def find_csv_files(data_dir: str) -> list:
    """หาไฟล์ CSV ทั้งหมดในโฟลเดอร์ ถ้าไม่เจอชื่อมาตรฐานจะ fallback ไปหาไฟล์ .csv ทั้งหมด"""
    expected_paths = [os.path.join(data_dir, f) for f in EXPECTED_FILES]
    found = [p for p in expected_paths if os.path.exists(p)]

    if len(found) == len(EXPECTED_FILES):
        print(f"[OK] พบไฟล์ครบตามชื่อมาตรฐานทั้ง {len(found)} ไฟล์")
        return found

    # fallback: ดึงไฟล์ .csv ทั้งหมดในโฟลเดอร์
    all_csv = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    print(f"[WARNING] ไม่พบชื่อไฟล์มาตรฐานครบทุกไฟล์ "
          f"-> ใช้ไฟล์ .csv ทั้งหมดที่เจอในโฟลเดอร์แทน ({len(all_csv)} ไฟล์)")
    for f in all_csv:
        print("   -", os.path.basename(f))
    return all_csv


def load_and_merge(file_list: list) -> pd.DataFrame:
    """โหลดไฟล์ CSV ทั้งหมดแล้วรวมเป็น DataFrame เดียว"""
    dfs = []
    for path in file_list:
        print(f"กำลังโหลด: {os.path.basename(path)} ...")
        # encoding='latin1' ป้องกันปัญหา decode error ที่พบบ่อยใน CICIDS2017
        df = pd.read_csv(path, encoding="latin1", low_memory=False)

        # แก้ปัญหาชื่อคอลัมน์มีช่องว่างนำหน้า/ตามหลัง เช่น " Label" -> "Label"
        df.columns = df.columns.str.strip()

        df["source_file"] = os.path.basename(path)  # เก็บไว้เผื่อ trace ย้อนกลับ
        print(f"   -> shape: {df.shape}")
        dfs.append(df)

    merged = pd.concat(dfs, axis=0, ignore_index=True)
    print(f"\n[OK] รวมข้อมูลทั้งหมดแล้ว shape สุดท้าย: {merged.shape}")
    return merged


def run_eda(df: pd.DataFrame, report_path: str):
    """สำรวจข้อมูลเบื้องต้นแล้วเขียนสรุปลงไฟล์ report"""
    lines = []

    def log(msg=""):
        print(msg)
        lines.append(str(msg))

    log("=" * 70)
    log("EDA REPORT - CICIDS2017")
    log("=" * 70)

    # ---- ภาพรวมของข้อมูล ----
    log(f"\n[1] จำนวนแถวทั้งหมด: {df.shape[0]:,}")
    log(f"    จำนวนคอลัมน์ทั้งหมด: {df.shape[1]}")

    # ---- รายชื่อคอลัมน์ ----
    log("\n[2] รายชื่อคอลัมน์ทั้งหมด:")
    for i, col in enumerate(df.columns, 1):
        log(f"    {i:>3}. {col} ({df[col].dtype})")

    # ---- ค่า Label / class distribution ----
    label_col = "Label" if "Label" in df.columns else None
    if label_col:
        log(f"\n[3] การกระจายตัวของ Label ('{label_col}'):")
        vc = df[label_col].value_counts()
        pct = df[label_col].value_counts(normalize=True) * 100
        for label, count in vc.items():
            log(f"    {label:<30} {count:>10,}  ({pct[label]:.3f}%)")
    else:
        log("\n[3] [WARNING] ไม่พบคอลัมน์ 'Label' กรุณาตรวจสอบชื่อคอลัมน์ Label ที่แท้จริง")

    # ---- Missing values ----
    log("\n[4] จำนวน Missing Values ต่อคอลัมน์ (แสดงเฉพาะคอลัมน์ที่มี > 0):")
    missing = df.isnull().sum()
    missing = missing[missing > 0].sort_values(ascending=False)
    if len(missing) == 0:
        log("    ไม่พบ Missing Values")
    else:
        for col, cnt in missing.items():
            log(f"    {col:<30} {cnt:>10,}  ({cnt/len(df)*100:.3f}%)")

    # ---- Infinite values (พบบ่อยในคอลัมน์ Flow Bytes/s, Flow Packets/s) ----
    log("\n[5] จำนวน Infinite Values ต่อคอลัมน์ตัวเลข (แสดงเฉพาะที่มี > 0):")
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    inf_counts = {}
    for col in numeric_cols:
        cnt = np.isinf(df[col]).sum()
        if cnt > 0:
            inf_counts[col] = cnt
    if not inf_counts:
        log("    ไม่พบ Infinite Values")
    else:
        for col, cnt in sorted(inf_counts.items(), key=lambda x: -x[1]):
            log(f"    {col:<30} {cnt:>10,}")

    # ---- Duplicate rows ----
    dup_count = df.duplicated().sum()
    log(f"\n[6] จำนวนแถวที่ซ้ำกัน (Duplicate rows): {dup_count:,} "
        f"({dup_count/len(df)*100:.3f}%)")

    # ---- ประเภทข้อมูล (numeric vs categorical) ----
    log(f"\n[7] จำนวนคอลัมน์ตัวเลข (numeric): {len(numeric_cols)}")
    non_numeric = df.select_dtypes(exclude=[np.number]).columns.tolist()
    log(f"    จำนวนคอลัมน์ที่ไม่ใช่ตัวเลข (categorical/text): {len(non_numeric)}")
    log(f"    รายชื่อ: {non_numeric}")

    # ---- สถิติเชิงพรรณนาของคอลัมน์ตัวเลข (ย่อ) ----
    log("\n[8] สถิติเชิงพรรณนาเบื้องต้น (5 คอลัมน์แรกเป็นตัวอย่าง):")
    log(df[numeric_cols[:5]].describe().to_string())

    # บันทึกลงไฟล์
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n[OK] บันทึกรายงาน EDA ไว้ที่: {report_path}")


def main():
    files = find_csv_files(DATA_DIR)
    if not files:
        raise FileNotFoundError(
            f"ไม่พบไฟล์ CSV ใดๆ ในโฟลเดอร์ {DATA_DIR} กรุณาตรวจสอบ path"
        )

    df = load_and_merge(files)

    # บันทึกข้อมูลรวม (parquet เร็วและเล็กกว่า CSV มาก เหมาะกับข้อมูลใหญ่)
    merged_path = os.path.join(OUTPUT_DIR, "merged_raw.parquet")
    df.to_parquet(merged_path, index=False)
    print(f"[OK] บันทึกข้อมูลรวมไว้ที่: {merged_path}")

    run_eda(df, os.path.join(OUTPUT_DIR, "eda_report.txt"))


if __name__ == "__main__":
    main()

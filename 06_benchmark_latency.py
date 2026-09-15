"""
06_benchmark_latency.py
=========================
วัดความเร็วประมวลผลจริงของ Hybrid Detection Engine เทียบกับ Time Budget
ตามตารางที่ 13 ในบทที่ 3 (Data Preprocessing ≤200ms, Hybrid Detection ≤100ms)

หมายเหตุสำคัญ: สคริปต์นี้วัดได้เฉพาะส่วนที่เป็นโมเดล ML โดยตรง (Data Preprocessing +
Hybrid Detection) เท่านั้น ส่วน Packet Capture, Risk Assessment, Incident Logging,
Dashboard Update และ LINE Messaging API เป็นการทำงานระดับระบบ (เครือข่าย, ฐานข้อมูล,
เบราว์เซอร์, API ภายนอก) ซึ่งต้องวัดจากการรันระบบเต็มรูปแบบผ่าน app.py จริงเท่านั้น
"""
import os
import time
import numpy as np
import pandas as pd

from hybrid_engine import HybridDetector

DATA_PATH = "./output/selected_data.parquet"
OUTPUT_DIR = "./output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

N_SAMPLES = 2000  # จำนวนโฟลว์ที่ใช้ทดสอบวัดเวลา (สุ่มจากทุกคลาส)

# Time Budget ตามตารางที่ 13 ในบทที่ 3 (หน่วย: ms)
BUDGET_PREPROCESSING_MS = 200
BUDGET_DETECTION_MS = 100
BUDGET_ML_TOTAL_MS = BUDGET_PREPROCESSING_MS + BUDGET_DETECTION_MS  # 300 ms


def summarize(times, name):
    arr = np.array(times)
    return {
        "metric": name,
        "mean_ms": round(float(arr.mean()), 3),
        "median_ms": round(float(np.median(arr)), 3),
        "p95_ms": round(float(np.percentile(arr, 95)), 3),
        "p99_ms": round(float(np.percentile(arr, 99)), 3),
        "max_ms": round(float(arr.max()), 3),
        "min_ms": round(float(arr.min()), 3),
    }


def run_benchmark():
    print("กำลังโหลด Hybrid Detector Engine...")
    detector = HybridDetector()

    print(f"กำลังโหลดข้อมูลตัวอย่างจาก {DATA_PATH} ...")
    df = pd.read_parquet(DATA_PATH)
    sample_df = df.sample(n=min(N_SAMPLES, len(df)), random_state=42)

    preprocessing_times, detection_times, total_times = [], [], []

    print(f"กำลังทดสอบความเร็วด้วยข้อมูล {len(sample_df)} โฟลว์ (Warm-up 1 ครั้งก่อน)...")

    # Warm-up call แรกไม่นับรวมในสถิติ (กัน overhead จากการโหลด/cache ครั้งแรก)
    warmup_row = sample_df.iloc[0].drop('Label').to_dict()
    detector.predict_flow(warmup_row)

    for _, row in sample_df.iterrows():
        flow_dict = row.drop('Label').to_dict()

        t_start = time.perf_counter()
        result = detector.predict_flow(flow_dict)
        t_end = time.perf_counter()

        preprocessing_times.append(result["preprocessing_time_ms"])
        detection_times.append(result["detection_time_ms"])
        total_times.append((t_end - t_start) * 1000)

    summary_rows = [
        summarize(preprocessing_times, "Data Preprocessing (Scaler Transform)"),
        summarize(detection_times, "Hybrid Detection (RF + IF Cascade)"),
        summarize(total_times, "รวม ML Pipeline (Preprocessing + Detection)"),
    ]
    summary_df = pd.DataFrame(summary_rows)

    print("\n" + "=" * 70)
    print(" ผลการวัดความเร็วประมวลผล (Latency Benchmark) ")
    print("=" * 70)
    print(summary_df.to_string(index=False))

    total_row = summary_df[summary_df['metric'].str.contains('รวม')].iloc[0]
    mean_total = total_row['mean_ms']
    p95_total = total_row['p95_ms']

    print(f"\n[เทียบกับ Time Budget ตารางที่ 13]")
    print(f"  งบเวลาที่ตั้งไว้ (Data Preprocessing + Hybrid Detection) = {BUDGET_ML_TOTAL_MS} ms")
    print(f"  เวลาเฉลี่ยที่วัดได้จริง (Mean)  = {mean_total:.3f} ms  "
          f"-> {'ผ่านเกณฑ์' if mean_total <= BUDGET_ML_TOTAL_MS else 'เกินเกณฑ์'}")
    print(f"  เวลาที่ 95th percentile (P95) = {p95_total:.3f} ms  "
          f"-> {'ผ่านเกณฑ์' if p95_total <= BUDGET_ML_TOTAL_MS else 'เกินเกณฑ์'}")

    print("\n[หมายเหตุสำคัญ] ผลนี้วัดเฉพาะส่วนโมเดล ML (Data Preprocessing + Hybrid Detection)")
    print("เท่านั้น ยังไม่รวม Packet Capture (~100ms), Risk Assessment (~50ms), Incident")
    print("Logging (~50ms), Dashboard Update (~100ms) และ LINE Messaging API (~150ms) ตาม")
    print("ตารางที่ 13 ซึ่งต้องวัดจากการรันระบบเต็มรูปแบบผ่าน app.py จริง (เช่น log เวลาที่")
    print("endpoint /api/simulate_traffic ใช้ทั้งหมด รวม DB และ LINE API) จึงจะได้ End-to-End")
    print("Response Time ที่สมบูรณ์ตามนิยามในบทที่ 2")

    summary_path = os.path.join(OUTPUT_DIR, "latency_benchmark_results.csv")
    summary_df.to_csv(summary_path, index=False)
    print(f"\n[OK] บันทึกผลการวัดความเร็วไว้ที่: {summary_path}")


if __name__ == '__main__':
    run_benchmark()
import os
import time
import joblib
import json
import numpy as np
import pandas as pd


class HybridDetector:
    def __init__(self, model_dir="./models", feature_file=None):
        rf_path = os.path.join(model_dir, "random_forest_model.pkl")
        iso_path = os.path.join(model_dir, "isolation_forest_model.pkl")
        scaler_path = os.path.join(model_dir, "scaler.pkl")
        feature_order_path = os.path.join(model_dir, "feature_order.json")

        print("กำลังโหลดโมเดล Machine Learning...")
        self.rf_model = joblib.load(rf_path)
        self.iso_model = joblib.load(iso_path)

        # สำคัญมาก: ต้องโหลด scaler ตัวเดียวกับที่ใช้ตอนฝึกโมเดล (05_train_final_model.py)
        # ไม่งั้นข้อมูลที่ส่งเข้า predict() จะอยู่คนละสเกลกับตอนฝึก ทำให้ผลผิดเพี้ยนทั้งหมด
        if not os.path.exists(scaler_path):
            raise FileNotFoundError(
                f"ไม่พบ {scaler_path} — กรุณารัน 05_train_final_model.py เวอร์ชันล่าสุดก่อน "
                f"(เวอร์ชันที่มีการบันทึก scaler.pkl ด้วย)"
            )
        self.scaler = joblib.load(scaler_path)
        print("[OK] โหลด scaler.pkl เรียบร้อย")

        # ใช้ feature_order.json จาก models/ (บันทึกตอนฝึกโมเดลจริงใน 05) เป็นหลัก
        # เพื่อให้ลำดับคอลัมน์ตรงกับตอน fit scaler เป๊ะๆ ถ้ายังไม่มีไฟล์นี้ (ยังไม่ได้รัน
        # 05 เวอร์ชันใหม่) จะ fallback ไปใช้ output/selected_features.json แทน
        if feature_file is None:
            if os.path.exists(feature_order_path):
                feature_file = feature_order_path
            else:
                feature_file = "./output/selected_features.json"
                print("[WARNING] ไม่พบ models/feature_order.json -> ใช้ "
                      "output/selected_features.json แทน (ควรรัน 05_train_final_model.py "
                      "เวอร์ชันล่าสุดเพื่อความชัวร์เรื่องลำดับ feature)")

        with open(feature_file, 'r', encoding='utf-8') as f:
            self.selected_features = json.load(f)

        print(f"[OK] โหลดรายชื่อ Feature ({len(self.selected_features)} ตัว) จาก {feature_file}")

    def predict_flow(self, flow_data_dict):
        """
        รับข้อมูลทราฟฟิก 1 โฟลว์ (Dictionary) แล้วประมวลผลผ่าน Cascade Hybrid Engine
        """
        # จับเวลาแยกส่วน Data Preprocessing กับ Hybrid Detection เพื่อใช้เทียบกับ
        # Time Budget ตารางที่ 13 ในบทที่ 3 (ดู 06_benchmark_latency.py)
        t0 = time.perf_counter()

        # แปลงเป็น DataFrame และดึงเฉพาะ Top Features ที่เลือกไว้ (เรียงลำดับเดียวกับตอนฝึก)
        df_input = pd.DataFrame([flow_data_dict])
        df_features = df_input[self.selected_features]

        # ต้อง transform ด้วย scaler ตัวเดียวกับตอนฝึกก่อนเสมอ (StandardScaler)
        df_features_scaled = pd.DataFrame(
            self.scaler.transform(df_features),
            columns=self.selected_features,
        )

        t1 = time.perf_counter()

        # Step 1: ส่งเข้า Random Forest (Supervised - Known Attack)
        rf_pred = self.rf_model.predict(df_features_scaled)[0]

        if rf_pred != 'BENIGN':
            # ตรวจพบ Known Attack
            detection_type = "Known Attack"
            attack_type = rf_pred
            risk_score = 90
            risk_level = "High"
        else:
            # Step 2: หาก RF ทายว่า normal (BENIGN) -> ส่งต่อไปยัง Isolation Forest
            if_pred = self.iso_model.predict(df_features_scaled)[0]
            if if_pred == -1:
                # Isolation Forest พบความผิดปกติ -> Unknown Attack (Anomaly)
                detection_type = "Unknown Attack"
                attack_type = "Anomaly (Unknown)"
                risk_score = 60
                risk_level = "Medium"
            else:
                # ปกติทั้งคู่ -> Normal Traffic
                detection_type = "Normal Traffic"
                attack_type = "Normal"
                risk_score = 10
                risk_level = "Low"

        t2 = time.perf_counter()

        return {
            "detection_type": detection_type,
            "attack_type": attack_type,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "preprocessing_time_ms": round((t1 - t0) * 1000, 3),
            "detection_time_ms": round((t2 - t1) * 1000, 3),
        }


if __name__ == '__main__':
    detector = HybridDetector()
    print("[OK] Hybrid Detector Engine พร้อมใช้งาน!")